use std::collections::HashMap;
use std::{env, fs, process};

use object::write;
use object::{
    Object, ObjectSection, ObjectSymbol, RelocationTarget, SectionKind, SymbolFlags, SymbolSection,
};

mod dwarf;
use dwarf::*;

fn main() {
    env_logger::init();

    let mut args = env::args();
    if args.len() != 3 {
        eprintln!("Usage: {} <infile> <outfile>", args.next().unwrap());
        process::exit(1);
    }

    args.next();
    let in_file_path = args.next().unwrap();
    let out_file_path = args.next().unwrap();

    let in_file = match fs::File::open(&in_file_path) {
        Ok(file) => file,
        Err(err) => {
            eprintln!("Failed to open file '{}': {}", in_file_path, err,);
            process::exit(1);
        }
    };
    let in_file = match unsafe { memmap2::Mmap::map(&in_file) } {
        Ok(mmap) => mmap,
        Err(err) => {
            eprintln!("Failed to map file '{}': {}", in_file_path, err,);
            process::exit(1);
        }
    };
    let in_object = match object::File::parse(&*in_file) {
        Ok(object) => object,
        Err(err) => {
            eprintln!("Failed to parse file '{}': {}", in_file_path, err);
            process::exit(1);
        }
    };

    let mut out_object = write::Object::new(
        in_object.format(),
        in_object.architecture(),
        in_object.endianness(),
    );
    out_object.mangling = write::Mangling::None;
    out_object.flags = in_object.flags();

    let mut out_sections = HashMap::new();
    for in_section in in_object.sections() {
        if in_section.kind() == SectionKind::Metadata || is_rewrite_dwarf_section(&in_section) {
            continue;
        }
        let segment_name = in_section
            .segment_name()
            .unwrap()
            .unwrap_or("")
            .as_bytes()
            .to_vec();
        let name = in_section.name().unwrap_or("").as_bytes().to_vec();
        let section_id = out_object.add_section(segment_name, name, in_section.kind());
        let out_section = out_object.section_mut(section_id);
        if out_section.is_bss() {
            out_section.append_bss(in_section.size(), in_section.align());
        } else {
            out_section.set_data(in_section.data().unwrap(), in_section.align());
        }
        out_section.flags = in_section.flags();
        out_sections.insert(in_section.index(), section_id);
    }

    let mut out_symbols = HashMap::new();
    for in_symbol in in_object.symbols() {
        let (section, value) = match in_symbol.section() {
            SymbolSection::None => (write::SymbolSection::None, in_symbol.address()),
            SymbolSection::Undefined => (write::SymbolSection::Undefined, in_symbol.address()),
            SymbolSection::Absolute => (write::SymbolSection::Absolute, in_symbol.address()),
            SymbolSection::Common => (write::SymbolSection::Common, in_symbol.address()),
            SymbolSection::Section(index) => {
                let out_section = if let Some(s) = out_sections.get(&index).cloned() {
                    s
                } else {
                    // Must be a section that we are rewriting.
                    continue;
                };
                (
                    write::SymbolSection::Section(out_section),
                    in_symbol.address() - in_object.section_by_index(index).unwrap().address(),
                )
            }
            _ => panic!("unknown symbol section for {:?}", in_symbol),
        };
        let flags = match in_symbol.flags() {
            SymbolFlags::None => SymbolFlags::None,
            SymbolFlags::Elf { st_info, st_other } => SymbolFlags::Elf { st_info, st_other },
            SymbolFlags::MachO { n_desc } => SymbolFlags::MachO { n_desc },
            SymbolFlags::CoffSection {
                selection,
                associative_section,
            } => {
                let associative_section = associative_section
                    .as_ref()
                    .map(|x| *out_sections.get(x).unwrap());
                SymbolFlags::CoffSection {
                    selection,
                    associative_section,
                }
            }
            _ => panic!("unknown symbol flags for {:?}", in_symbol),
        };
        let out_symbol = write::Symbol {
            name: in_symbol.name().unwrap_or("").as_bytes().to_vec(),
            value,
            size: in_symbol.size(),
            kind: in_symbol.kind(),
            scope: in_symbol.scope(),
            weak: in_symbol.is_weak(),
            section,
            flags,
        };
        let symbol_id = out_object.add_symbol(out_symbol);
        out_symbols.insert(in_symbol.index(), symbol_id);
    }

    for in_section in in_object.sections() {
        if in_section.kind() == SectionKind::Metadata || is_rewrite_dwarf_section(&in_section) {
            continue;
        }
        let out_section = *out_sections.get(&in_section.index()).unwrap();
        for (offset, in_relocation) in in_section.relocations() {
            let symbol = match in_relocation.target() {
                RelocationTarget::Symbol(symbol) => *out_symbols.get(&symbol).unwrap(),
                RelocationTarget::Section(section) => {
                    out_object.section_symbol(*out_sections.get(&section).unwrap())
                }
                _ => unimplemented!(),
            };
            let out_relocation = write::Relocation {
                offset,
                symbol,
                addend: in_relocation.addend(),
                flags: in_relocation.flags(),
            };
            out_object
                .add_relocation(out_section, out_relocation)
                .unwrap();
        }
    }

    rewrite_dwarf(&in_object, &mut out_object, &out_symbols);

    let out_data = out_object.write().unwrap();
    if let Err(err) = fs::write(&out_file_path, out_data) {
        eprintln!("Failed to write file '{}': {}", out_file_path, err);
        process::exit(1);
    }
}
