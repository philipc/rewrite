use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashMap;
use std::convert::TryInto;

use gimli::read::EndianSlice;
use gimli::write::{Address, EndianVec};
use gimli::{self, read, write, LittleEndian};
use object::write as object_write;
use object::{self, Object, ObjectSection, ObjectSymbol, SymbolIndex};

pub fn rewrite_dwarf(
    file: &object::File<'_>,
    out_object: &mut object_write::Object,
    symbols: &HashMap<SymbolIndex, object_write::SymbolId>,
) {
    /*
    // Define the sections we can't convert yet.
    for section in in_object.sections() {
        if let Some(name) = section.name() {
            if !is_rewrite_dwarf_section(&section) {
                artifact.declare(name, Decl::debug_section()).unwrap();
                artifact
                    .define(name, section.uncompressed_data().into_owned())
                    .unwrap();
            }
        }
    }
    */

    fn get_reader<'a>(
        data: &'a [u8],
        relocations: &'a ReadRelocationMap,
        addresses: &'a ReadAddressMap,
    ) -> ReaderRelocate<'a, EndianSlice<'a, LittleEndian>> {
        let section = EndianSlice::new(data, LittleEndian);
        ReaderRelocate {
            relocations,
            addresses,
            section,
            reader: section,
        }
    }

    let addresses = ReadAddressMap::default();
    let dwarf_data =
        read::DwarfSections::load(|id| -> Result<_, ()> { Ok(get_section(file, id.name())) })
            .unwrap();
    let dwarf = dwarf_data.borrow(|(data, relocs)| get_reader(data, relocs, &addresses));
    /*
    let (eh_frame_data, eh_frame_relocs) = get_section(file, ".eh_frame");
    let eh_frame = read::EhFrame::from(get_reader(&eh_frame_data, &eh_frame_relocs, &addresses));
    */

    let convert_address = |index| Some(addresses.get(index as usize));

    let mut dwarf = match write::Dwarf::from(&dwarf, &convert_address) {
        Ok(dwarf) => dwarf,
        Err(write::ConvertError::Read(err)) => {
            eprintln!("dwarf convert: {}", dwarf.format_error(err));
            panic!();
        }
        Err(e) => panic!("{:?}", e),
    };
    // TODO: only add relocations for relocatable files
    let mut sections = write::Sections::new(WriterRelocate::new(EndianVec::new(LittleEndian)));
    dwarf.write(&mut sections).unwrap();
    let mut section_symbols = HashMap::new();

    let _: Result<(), gimli::Error> = sections.for_each_mut(|id, w| {
        define(
            id,
            out_object,
            &mut section_symbols,
            symbols,
            w.writer.take(),
            &w.relocations,
        );
        Ok(())
    });

    /*
    let frame = write::FrameTable::from(&eh_frame, &convert_address).unwrap();
    let mut out_eh_frame = write::EhFrame(WriterRelocate::new(EndianVec::new(LittleEndian)));
    frame.write_eh_frame(&mut out_eh_frame).unwrap();
    define(
        gimli::SectionId::EhFrame,
        out_object,
        &mut section_symbols,
        symbols,
        out_eh_frame.0.writer.take(),
        &out_eh_frame.0.relocations,
    );
    */
}

fn define(
    id: gimli::SectionId,
    out_object: &mut object_write::Object,
    section_symbols: &mut HashMap<gimli::SectionId, object_write::SymbolId>,
    symbols: &HashMap<SymbolIndex, object_write::SymbolId>,
    data: Vec<u8>,
    relocations: &[Relocation],
) {
    if data.is_empty() {
        return;
    }

    let section_id = out_object.add_section(
        vec![],
        id.name().as_bytes().to_vec(),
        object::SectionKind::Other,
    );
    let section = out_object.section_mut(section_id);
    section.set_data(data, 1);
    let symbol_id = out_object.section_symbol(section_id);
    section_symbols.insert(id, symbol_id);
    for relocation in link(section_symbols, symbols, relocations) {
        out_object.add_relocation(section_id, relocation).unwrap();
    }
}

fn link(
    section_symbols: &HashMap<gimli::SectionId, object_write::SymbolId>,
    symbols: &HashMap<SymbolIndex, object_write::SymbolId>,
    relocations: &[Relocation],
) -> Vec<object_write::Relocation> {
    let mut out_relocations = Vec::new();
    for reloc in relocations {
        match *reloc {
            Relocation::Section {
                offset,
                section,
                addend,
                size,
            } => {
                let symbol = match section_symbols.get(&section) {
                    Some(s) => *s,
                    None => {
                        eprintln!("Missing section {}", section.name());
                        continue;
                    }
                };
                out_relocations.push(object_write::Relocation {
                    offset,
                    symbol,
                    addend: addend as i64,
                    flags: object::RelocationFlags::Generic {
                        size: size * 8,
                        kind: object::RelocationKind::Absolute,
                        encoding: object::RelocationEncoding::Generic,
                    },
                });
            }
            Relocation::Symbol {
                offset,
                symbol,
                addend,
                kind,
                size,
            } => {
                let symbol = *symbols.get(&symbol).unwrap();
                out_relocations.push(object_write::Relocation {
                    offset,
                    symbol,
                    addend: addend as i64,
                    flags: object::RelocationFlags::Generic {
                        size: size * 8,
                        kind,
                        encoding: object::RelocationEncoding::Generic,
                    },
                });
            }
        }
    }
    out_relocations
}

pub fn is_rewrite_dwarf_section(section: &object::Section<'_, '_>) -> bool {
    if let Ok(name) = section.name() {
        if name.starts_with(".debug_") {
            match name {
                ".debug_aranges" | ".debug_abbrev" | ".debug_addr" | ".debug_info"
                | ".debug_line" | ".debug_line_str" | ".debug_loc" | ".debug_loclists"
                | ".debug_pubnames" | ".debug_pubtypes" | ".debug_ranges" | ".debug_rnglists"
                | ".debug_str" | ".debug_str_offsets" => {
                    return true;
                }
                _ => return false,
            }
        }
        /*
        if name == ".eh_frame" {
            return true;
        }
        */
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
        None => return (Cow::Borrowed(&[]), relocations),
    };
    for (offset64, mut relocation) in section.relocations() {
        let offset = offset64.try_into().unwrap();
        match relocation.kind() {
            object::RelocationKind::Absolute | object::RelocationKind::Relative => {
                match relocation.target() {
                    object::RelocationTarget::Symbol(symbol) => {
                        if let Ok(symbol) = file.symbol_by_index(symbol) {
                            let addend = symbol.address().wrapping_add(relocation.addend() as u64);
                            relocation.set_addend(addend as i64);
                            println!("Adding reloc {} {:?}", offset, relocation);
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
                            "Unsupported relocation target for section {} at offset 0x{:08x}",
                            section.name().unwrap(),
                            offset
                        );
                    }
                }
            }
            _ => {
                println!(
                    "Unsupported relocation kind for section {} at offset 0x{:08x}",
                    section.name().unwrap(),
                    offset
                );
            }
        }
    }

    let data = section.uncompressed_data().unwrap();
    (data, relocations)
}

// gimli::read::Reader::read_address() returns u64, but gimli::write data structures wants
// a gimli::write::Address. To work around this, every time we read an address we add
// an Address to this map, and return that index in read_address(). Then later we
// convert that index back into the Address.
// Note that addresses 0 and !0 can have special meaning in DWARF (eg for range lists).
// 0 can also be appear as a default value for DW_AT_low_pc.
#[derive(Debug, Default)]
struct ReadAddressMap {
    addresses: RefCell<Vec<Address>>,
}

impl ReadAddressMap {
    fn add(&self, address: Address) -> usize {
        if address == Address::Constant(0) {
            // Must be zero because this may not be an address.
            return 0;
        }
        let mut addresses = self.addresses.borrow_mut();
        addresses.push(address);
        // Non-zero
        addresses.len()
    }

    fn get(&self, index: usize) -> Address {
        if index == 0 {
            Address::Constant(0)
        } else {
            let addresses = self.addresses.borrow();
            addresses[index - 1]
        }
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
                object::RelocationKind::Absolute => {
                    if relocation.has_implicit_addend() {
                        // Use the explicit addend too, because it may have the symbol value.
                        return value.wrapping_add(relocation.addend() as u64);
                    } else {
                        return relocation.addend() as u64;
                    }
                }
                _ => {}
            }
        }
        value
    }

    fn relocate_address(&self, offset: usize, value: u64) -> Option<Address> {
        if let Some(relocation) = self.relocations.get(&offset) {
            let symbol = match relocation.target() {
                object::RelocationTarget::Symbol(symbol) => symbol.0,
                _ => unimplemented!(),
            };
            let addend = match relocation.kind() {
                object::RelocationKind::Absolute | object::RelocationKind::Relative => {
                    if relocation.has_implicit_addend() {
                        // Use the explicit addend too, because it may have the symbol value.
                        value.wrapping_add(relocation.addend() as u64) as i64
                    } else {
                        relocation.addend()
                    }
                }
                _ => unimplemented!(),
            };
            Some(Address::Symbol { symbol, addend })
        } else {
            None
        }
    }
}

impl<'a, R: read::Reader<Offset = usize>> read::Reader for ReaderRelocate<'a, R> {
    type Endian = R::Endian;
    type Offset = R::Offset;

    fn read_address(&mut self, address_size: u8) -> read::Result<u64> {
        let offset = self.reader.offset_from(&self.section);
        let value = self.reader.read_address(address_size)?;
        //println!("read_address {} {}", offset, value);
        let address = ReaderRelocate::relocate_address(self, offset, value)
            .unwrap_or(Address::Constant(value));
        //println!("relocate_address {} {:?}", offset, address);
        Ok(self.addresses.add(address) as u64)
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
    fn offset_id(&self) -> gimli::ReaderOffsetId {
        self.reader.offset_id()
    }

    #[inline]
    fn lookup_offset_id(&self, id: gimli::ReaderOffsetId) -> Option<Self::Offset> {
        self.reader.lookup_offset_id(id)
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
    fn to_slice(&self) -> read::Result<Cow<'_, [u8]>> {
        self.reader.to_slice()
    }

    #[inline]
    fn to_string(&self) -> read::Result<Cow<'_, str>> {
        self.reader.to_string()
    }

    #[inline]
    fn to_string_lossy(&self) -> read::Result<Cow<'_, str>> {
        self.reader.to_string_lossy()
    }

    #[inline]
    fn read_slice(&mut self, buf: &mut [u8]) -> read::Result<()> {
        self.reader.read_slice(buf)
    }
}

#[derive(Debug, Clone)]
pub enum Relocation {
    Section {
        offset: u64,
        section: gimli::SectionId,
        addend: i32,
        size: u8,
    },
    Symbol {
        offset: u64,
        symbol: SymbolIndex,
        addend: i32,
        kind: object::RelocationKind,
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

    fn len(&self) -> usize {
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
            Address::Constant(val) => self.write_udata(val, size),
            Address::Symbol { symbol, addend } => {
                let offset = self.len() as u64;
                self.relocations.push(Relocation::Symbol {
                    offset,
                    symbol: SymbolIndex(symbol),
                    addend: addend as i32,
                    kind: object::RelocationKind::Absolute,
                    size,
                });
                self.write_udata(0, size)
            }
        }
    }

    fn write_eh_pointer(
        &mut self,
        address: Address,
        eh_pe: gimli::DwEhPe,
        _size: u8,
    ) -> write::Result<()> {
        println!("write_eh_pointer {} {:?}", self.len(), address);
        match (address, eh_pe.application(), eh_pe.format()) {
            (Address::Constant(value), gimli::DW_EH_PE_absptr, gimli::DW_EH_PE_sdata4) => {
                self.write_u32(value as u32)
            }
            (Address::Symbol { symbol, addend }, gimli::DW_EH_PE_pcrel, gimli::DW_EH_PE_sdata4) => {
                let offset = self.len() as u64;
                self.relocations.push(Relocation::Symbol {
                    offset,
                    symbol: SymbolIndex(symbol),
                    addend: addend as i32,
                    kind: object::RelocationKind::Relative,
                    size: 4,
                });
                self.write_u32(0)
            }
            _ => unimplemented!("{:?} {:?}", address, eh_pe),
        }
    }

    fn write_offset(
        &mut self,
        val: usize,
        section: gimli::SectionId,
        size: u8,
    ) -> write::Result<()> {
        let offset = self.len() as u64;
        self.relocations.push(Relocation::Section {
            offset,
            section,
            addend: val as i32,
            size,
        });
        self.write_udata(0, size)
    }

    fn write_offset_at(
        &mut self,
        offset: usize,
        val: usize,
        section: gimli::SectionId,
        size: u8,
    ) -> write::Result<()> {
        self.relocations.push(Relocation::Section {
            offset: offset as u64,
            section,
            addend: val as i32,
            size,
        });
        self.write_udata_at(offset, 0, size)
    }
}
