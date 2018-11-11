use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashMap;

use faerie::{Artifact, Decl, Link, RelocOverride};
use gimli::read::EndianSlice;
use gimli::write::{Address, EndianVec, Section};
use gimli::{read, write, LittleEndian};
use goblin::elf;
use object::{self, Object, ObjectSection};

use symbol::SymbolMap;

pub fn rewrite_dwarf(file: &object::File, artifact: &mut Artifact, symbols: &SymbolMap) {
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

    fn get_reader<'a>(
        data: &'a [u8],
        relocations: &'a ReadRelocationMap,
        addresses: &'a ReadAddressMap,
    ) -> ReaderRelocate<'a, EndianSlice<'a, LittleEndian>> {
        let section = EndianSlice::new(data, LittleEndian);
        let reader = section.clone();
        ReaderRelocate {
            relocations,
            addresses,
            section,
            reader,
        }
    };

    let addresses = ReadAddressMap::default();
    let (debug_info_data, debug_info_relocs) = get_section(file, ".debug_info");
    let (debug_abbrev_data, debug_abbrev_relocs) = get_section(file, ".debug_abbrev");
    let (debug_str_data, debug_str_relocs) = get_section(file, ".debug_str");
    let from_debug_info =
        read::DebugInfo::from(get_reader(&debug_info_data, &debug_info_relocs, &addresses));
    let from_debug_abbrev = read::DebugAbbrev::from(get_reader(
        &debug_abbrev_data,
        &debug_abbrev_relocs,
        &addresses,
    ));
    let from_debug_str =
        read::DebugStr::from(get_reader(&debug_str_data, &debug_str_relocs, &addresses));

    let convert_address = |index| Some(addresses.get(index as usize));

    let mut strings = write::StringTable::default();
    let units = write::UnitTable::from(
        &from_debug_info,
        &from_debug_abbrev,
        &from_debug_str,
        &mut strings,
        &convert_address,
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
                symbol,
                addend,
                size,
            } => {
                let symbol = file.symbol_by_index(symbol as u64).unwrap();
                let (to, addend) = symbols.lookup_symbol_offset(file, &symbol, addend as u64);
                let reloc = match size {
                    4 => elf::reloc::R_X86_64_32,
                    8 => elf::reloc::R_X86_64_64,
                    _ => unimplemented!(),
                };
                artifact
                    .link_with(
                        Link {
                            from: ".debug_info",
                            to: &to,
                            at: offset,
                        },
                        RelocOverride {
                            reloc,
                            addend: addend as i32,
                        },
                    ).unwrap();
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

fn get_section<'data>(
    file: &object::File<'data>,
    name: &str,
) -> (Cow<'data, [u8]>, ReadRelocationMap) {
    let mut relocations = ReadRelocationMap::default();
    let section = match file.section_by_name(name) {
        Some(section) => section,
        None => return (Cow::Borrowed(&[][..]), relocations),
    };
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

    let data = section.uncompressed_data();
    (data, relocations)
}

// gimli::read::Reader::read_address() returns u64, but gimli::write data structures wants
// a gimli::write::Address. To work around this, every time we read an address we add
// an Address to this map, and return that index read_address(). Then later we
// convert that index back into the Address.
#[derive(Debug, Default)]
struct ReadAddressMap {
    addresses: RefCell<Vec<Address>>,
}

impl ReadAddressMap {
    fn add(&self, address: Address) -> usize {
        let mut addresses = self.addresses.borrow_mut();
        let index = addresses.len();
        addresses.push(address);
        index
    }

    fn get(&self, index: usize) -> Address {
        let addresses = self.addresses.borrow();
        addresses[index]
    }
}

#[derive(Debug, Clone)]
struct ReaderRelocate<'a, R: read::Reader<Offset = usize>> {
    relocations: &'a ReadRelocationMap,
    addresses: &'a ReadAddressMap,
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
        let address = if let Some(relocation) = self.relocations.get(&offset) {
            match relocation.kind() {
                object::RelocationKind::Direct32 | object::RelocationKind::Direct64 => {
                    let addend = if relocation.has_implicit_addend() {
                        // Use the explicit addend too, because it may have the symbol value.
                        value.wrapping_add(relocation.addend() as u64) as i64
                    } else {
                        relocation.addend()
                    };
                    Address::Relative {
                        symbol: relocation.symbol() as usize,
                        addend,
                    }
                }
                _ => unimplemented!(),
            }
        } else {
            Address::Absolute(value)
        };
        Ok(self.addresses.add(address) as u64)
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
        symbol: usize,
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
            Address::Relative { symbol, addend } => {
                let offset = self.len() as u64;
                self.relocations.push(Relocation::Symbol {
                    offset,
                    symbol,
                    addend: addend as i32,
                    size,
                });
                self.write_word(0, size)
            }
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
            addend: val as i32,
            size,
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
            addend: val as i32,
            size,
        });
        self.write_word_at(offset, 0, size)
    }
}
