use std::borrow::Cow;
use std::collections::HashMap;

use faerie::{Artifact, Decl, Link, RelocOverride};
use gimli::read::EndianSlice;
use gimli::write::{Address, EndianVec, Section};
use gimli::{read, write, LittleEndian};
use goblin::elf;
use object::{self, Object, ObjectSection};

pub fn rewrite_dwarf(file: &object::File, artifact: &mut Artifact) {
    // Define the sections we can't convert yet.
    for section in file.sections() {
        if let Some(name) = section.name() {
            if is_copy_dwarf_section(&section) {
                artifact.declare(name, Decl::DebugSection).unwrap();
                artifact
                    .define(name, section.uncompressed_data().into_owned())
                    .unwrap();
            }
        }
    }

    let get_section = |name| {
        let mut relocs = ReadRelocationMap::default();
        if let Some(ref section) = file.section_by_name(name) {
            read_dwarf_relocations(&mut relocs, file, section);
            (section.uncompressed_data(), relocs)
        } else {
            (Cow::Borrowed(&[][..]), relocs)
        }
    };
    fn get_reader<'a>(
        data: &'a [u8],
        relocations: &'a ReadRelocationMap,
    ) -> ReaderRelocate<'a, EndianSlice<'a, LittleEndian>> {
        let section = EndianSlice::new(data, LittleEndian);
        let reader = section.clone();
        ReaderRelocate {
            relocations,
            section,
            reader,
        }
    };
    let (debug_info_data, debug_info_relocs) = get_section(".debug_info");
    let from_debug_info = read::DebugInfo::from(get_reader(&debug_info_data, &debug_info_relocs));
    let (debug_abbrev_data, debug_abbrev_relocs) = get_section(".debug_abbrev");
    let from_debug_abbrev =
        read::DebugAbbrev::from(get_reader(&debug_abbrev_data, &debug_abbrev_relocs));
    let (debug_str_data, debug_str_relocs) = get_section(".debug_str");
    let from_debug_str = read::DebugStr::from(get_reader(&debug_str_data, &debug_str_relocs));

    let mut strings = write::StringTable::default();
    let units = write::UnitTable::from(
        &from_debug_info,
        &from_debug_abbrev,
        &from_debug_str,
        &mut strings,
        &|address| Some(Address::Absolute(address)),
    ).unwrap();

    let mut to_debug_str = write::DebugStr::from(WriterRelocate::new(EndianVec::new(LittleEndian)));
    let debug_str_offsets = strings.write(&mut to_debug_str).unwrap();

    let mut to_debug_info =
        write::DebugInfo::from(WriterRelocate::new(EndianVec::new(LittleEndian)));
    let mut to_debug_abbrev =
        write::DebugAbbrev::from(WriterRelocate::new(EndianVec::new(LittleEndian)));
    units
        .write(&mut to_debug_info, &mut to_debug_abbrev, &debug_str_offsets)
        .unwrap();

    artifact.declare(".debug_info", Decl::DebugSection).unwrap();
    artifact
        .declare(".debug_abbrev", Decl::DebugSection)
        .unwrap();
    artifact.declare(".debug_str", Decl::DebugSection).unwrap();

    let to_debug_info = to_debug_info.into_writer();
    let to_debug_abbrev = to_debug_abbrev.into_writer();
    let to_debug_str = to_debug_str.into_writer();
    artifact
        .define(".debug_info", to_debug_info.writer.into_vec())
        .unwrap();
    artifact
        .define(".debug_abbrev", to_debug_abbrev.writer.into_vec())
        .unwrap();
    artifact
        .define(".debug_str", to_debug_str.writer.into_vec())
        .unwrap();

    for reloc in to_debug_info.relocations {
        match reloc {
            Relocation::Section {
                offset,
                section,
                addend,
                size,
            } => {
                let reloc = match size {
                    4 => elf::reloc::R_X86_64_32,
                    8 => elf::reloc::R_X86_64_64,
                    _ => unimplemented!(),
                };
                artifact
                    .link_with(
                        Link {
                            from: ".debug_info",
                            to: section,
                            at: offset,
                        },
                        RelocOverride { reloc, addend },
                    ).unwrap();
            }
            Relocation::Symbol {
                offset,
                id,
                addend,
                size,
            } => {
                // TODO
            }
        }
    }

    assert!(to_debug_abbrev.relocations.is_empty());
    assert!(to_debug_str.relocations.is_empty());
}

pub fn is_copy_dwarf_section(section: &object::Section) -> bool {
    if let Some(name) = section.name() {
        if name.starts_with(".debug_") {
            match name {
                ".debug_info" | ".debug_abbrev" | ".debug_str" => return false,
                _ => return true,
            }
        }
    }
    false
}

type ReadRelocationMap = HashMap<usize, object::Relocation>;

fn read_dwarf_relocations(
    relocations: &mut ReadRelocationMap,
    file: &object::File,
    section: &object::Section,
) {
    for (offset64, mut relocation) in section.relocations() {
        let offset = offset64 as usize;
        if offset as u64 != offset64 {
            continue;
        }
        let offset = offset as usize;
        match relocation.kind() {
            object::RelocationKind::Direct32 | object::RelocationKind::Direct64 => {
                if let Some(symbol) = file.symbol_by_index(relocation.symbol()) {
                    let addend = symbol.address().wrapping_add(relocation.addend() as u64);
                    relocation.set_addend(addend as i64);
                    if relocations.insert(offset, relocation).is_some() {
                        println!(
                            "Multiple relocations for section {} at offset 0x{:08x}",
                            section.name().unwrap(),
                            offset
                        );
                    }
                } else {
                    println!(
                        "Relocation with invalid symbol for section {} at offset 0x{:08x}",
                        section.name().unwrap(),
                        offset
                    );
                }
            }
            _ => {
                println!(
                    "Unsupported relocation for section {} at offset 0x{:08x}",
                    section.name().unwrap(),
                    offset
                );
            }
        }
    }
}

#[derive(Debug, Clone)]
struct ReaderRelocate<'a, R: read::Reader<Offset = usize>> {
    relocations: &'a ReadRelocationMap,
    section: R,
    reader: R,
}

impl<'a, R: read::Reader<Offset = usize>> ReaderRelocate<'a, R> {
    fn relocate(&self, offset: usize, value: u64) -> u64 {
        if let Some(relocation) = self.relocations.get(&offset) {
            match relocation.kind() {
                object::RelocationKind::Direct32 | object::RelocationKind::Direct64 => {
                    if relocation.has_implicit_addend() {
                        // Use the explicit addend too, because it may have the symbol value.
                        return value.wrapping_add(relocation.addend() as u64);
                    } else {
                        return relocation.addend() as u64;
                    }
                }
                _ => {}
            }
        };
        value
    }
}

impl<'a, R: read::Reader<Offset = usize>> read::Reader for ReaderRelocate<'a, R> {
    type Endian = R::Endian;
    type Offset = R::Offset;

    fn read_address(&mut self, address_size: u8) -> read::Result<u64> {
        let offset = self.reader.offset_from(&self.section);
        let value = self.reader.read_address(address_size)?;
        //println!("read_address {} {}", offset, value);
        Ok(self.relocate(offset, value))
    }

    fn read_length(&mut self, format: gimli::Format) -> read::Result<usize> {
        let offset = self.reader.offset_from(&self.section);
        let value = self.reader.read_length(format)?;
        //println!("read_length {} {}", offset, value);
        <usize as read::ReaderOffset>::from_u64(self.relocate(offset, value as u64))
    }

    fn read_offset(&mut self, format: gimli::Format) -> read::Result<usize> {
        let offset = self.reader.offset_from(&self.section);
        let value = self.reader.read_offset(format)?;
        //println!("read_offset {} {}", offset, value);
        <usize as read::ReaderOffset>::from_u64(self.relocate(offset, value as u64))
    }

    fn read_sized_offset(&mut self, size: u8) -> read::Result<usize> {
        let offset = self.reader.offset_from(&self.section);
        let value = self.reader.read_sized_offset(size)?;
        //println!("read_sized_offset {} {}", offset, value);
        <usize as read::ReaderOffset>::from_u64(self.relocate(offset, value as u64))
    }

    #[inline]
    fn split(&mut self, len: Self::Offset) -> read::Result<Self> {
        let mut other = self.clone();
        other.reader.truncate(len)?;
        self.reader.skip(len)?;
        Ok(other)
    }

    // All remaining methods simply delegate to `self.reader`.

    #[inline]
    fn endian(&self) -> Self::Endian {
        self.reader.endian()
    }

    #[inline]
    fn len(&self) -> Self::Offset {
        self.reader.len()
    }

    #[inline]
    fn empty(&mut self) {
        self.reader.empty()
    }

    #[inline]
    fn truncate(&mut self, len: Self::Offset) -> read::Result<()> {
        self.reader.truncate(len)
    }

    #[inline]
    fn offset_from(&self, base: &Self) -> Self::Offset {
        self.reader.offset_from(&base.reader)
    }

    #[inline]
    fn find(&self, byte: u8) -> read::Result<Self::Offset> {
        self.reader.find(byte)
    }

    #[inline]
    fn skip(&mut self, len: Self::Offset) -> read::Result<()> {
        self.reader.skip(len)
    }

    #[inline]
    fn to_slice(&self) -> read::Result<Cow<[u8]>> {
        self.reader.to_slice()
    }

    #[inline]
    fn to_string(&self) -> read::Result<Cow<str>> {
        self.reader.to_string()
    }

    #[inline]
    fn to_string_lossy(&self) -> read::Result<Cow<str>> {
        self.reader.to_string_lossy()
    }

    #[inline]
    fn read_u8_array<A>(&mut self) -> read::Result<A>
    where
        A: Sized + Default + AsMut<[u8]>,
    {
        //let offset = self.reader.offset_from(&self.section);
        //println!("read_i8_array {} {} {}", offset, std::mem::size_of::<A>(), self.reader.len());
        self.reader.read_u8_array()
    }
}

#[derive(Debug, Clone)]
pub enum Relocation {
    Section {
        offset: u64,
        section: &'static str,
        addend: i32,
        size: u8,
    },
    Symbol {
        offset: u64,
        id: usize,
        addend: i32,
        size: u8,
    },
}

#[derive(Debug, Clone)]
struct WriterRelocate<W: write::Writer> {
    relocations: Vec<Relocation>,
    writer: W,
}

impl<W: write::Writer> WriterRelocate<W> {
    fn new(writer: W) -> Self {
        WriterRelocate {
            relocations: Vec::new(),
            writer,
        }
    }
}

impl<W: write::Writer> write::Writer for WriterRelocate<W> {
    type Endian = W::Endian;

    fn endian(&self) -> Self::Endian {
        self.writer.endian()
    }

    fn len(&mut self) -> usize {
        self.writer.len()
    }

    fn write(&mut self, bytes: &[u8]) -> write::Result<()> {
        self.writer.write(bytes)
    }

    fn write_at(&mut self, offset: usize, bytes: &[u8]) -> write::Result<()> {
        self.writer.write_at(offset, bytes)
    }

    fn write_address(&mut self, address: Address, size: u8) -> write::Result<()> {
        match address {
            Address::Absolute(val) => self.write_word(val, size),
            // TODO
            Address::Relative { .. } => Err(write::Error::InvalidAddress),
        }
    }

    fn write_offset(
        &mut self,
        val: usize,
        section: write::SectionKind,
        size: u8,
    ) -> write::Result<()> {
        let offset = self.len() as u64;
        let section = section.name();
        self.relocations.push(Relocation::Section {
            offset,
            section,
            size,
            addend: val as i32,
        });
        self.write_word(0, size)
    }

    fn write_offset_at(
        &mut self,
        offset: usize,
        val: usize,
        section: write::SectionKind,
        size: u8,
    ) -> write::Result<()> {
        let section = section.name();
        self.relocations.push(Relocation::Section {
            offset: offset as u64,
            section,
            size,
            addend: val as i32,
        });
        self.write_word_at(offset, 0, size)
    }
}
