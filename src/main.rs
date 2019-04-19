use std::collections::HashMap;
use std::{env, fs, process};

use env_logger;
use memmap;
use object::{self, Object, ObjectSection, SectionKind, SymbolKind};
use object_write as write;

mod dwarf;
use dwarf::*;

fn main() {
    env_logger::init();

    let arg_len = env::args().len();
    if arg_len != 3 {
        eprintln!("Usage: {} <from> <to>", env::args().next().unwrap());
        process::exit(1);
    }

    let from = env::args().nth(1).unwrap();
    let to = env::args().nth(2).unwrap();

    let file = match fs::File::open(&from) {
        Ok(file) => file,
        Err(err) => {
            println!("Failed to open file '{}': {}", from, err);
            return;
        }
    };
    let file = match unsafe { memmap::Mmap::map(&file) } {
        Ok(mmap) => mmap,
        Err(err) => {
            println!("Failed to map file '{}': {}", from, err);
            return;
        }
    };
    let in_object = match object::File::parse(&*file) {
        Ok(object) => object,
        Err(err) => {
            println!("Failed to parse file '{}': {}", from, err);
            return;
        }
    };

    let mut out_object = write::Object::new(in_object.machine());
    out_object.entry = in_object.entry();

    let mut out_sections = HashMap::new();
    for in_section in in_object.sections() {
        if in_section.kind() == SectionKind::Metadata || is_rewrite_dwarf_section(&in_section) {
            continue;
        }
        let out_section = write::Section {
            name: in_section.name().unwrap_or("").as_bytes().to_vec(),
            segment_name: in_section.segment_name().unwrap_or("").as_bytes().to_vec(),
            kind: in_section.kind(),
            address: in_section.address(),
            size: in_section.size(),
            align: in_section.align(),
            data: in_section.uncompressed_data().into(),
            relocations: Vec::new(),
        };
        let section_id = out_object.add_section(out_section);
        out_sections.insert(in_section.index(), section_id);
    }

    let mut out_symbols = HashMap::new();
    for (symbol_index, in_symbol) in in_object.symbols() {
        if in_symbol.kind() == SymbolKind::Null {
            continue;
        }
        let section = match in_symbol.section_index() {
            Some(s) => {
                if let Some(s) = out_sections.get(&s) {
                    Some(*s)
                } else {
                    // Must be a section that we are rewriting.
                    continue;
                }
            }
            None => None,
        };
        let out_symbol = write::Symbol {
            name: in_symbol.name().unwrap_or("").as_bytes().to_vec(),
            value: in_symbol.address(),
            size: in_symbol.size(),
            binding: in_symbol.binding(),
            kind: in_symbol.kind(),
            section,
        };
        let symbol_id = out_object.add_symbol(out_symbol);
        out_symbols.insert(symbol_index, symbol_id);
    }

    for in_section in in_object.sections() {
        if in_section.kind() == SectionKind::Metadata || is_rewrite_dwarf_section(&in_section) {
            continue;
        }
        let out_section =
            &mut out_object.sections[out_sections.get(&in_section.index()).unwrap().0];
        for (offset, in_relocation) in in_section.relocations() {
            let symbol = match out_symbols.get(&in_relocation.symbol()) {
                Some(s) => *s,
                None => {
                    eprintln!("skipping reloc {:x}, {:?}", offset, in_relocation);
                    continue;
                }
            };
            let out_relocation = write::Relocation {
                offset,
                symbol,
                kind: in_relocation.kind(),
                size: in_relocation.size(),
                addend: in_relocation.addend(),
            };
            out_section.relocations.push(out_relocation);
        }
    }

    rewrite_dwarf(&in_object, &mut out_object, &out_symbols);

    let out_data = out_object.write();
    if let Err(err) = fs::write(&to, out_data) {
        println!("Failed to write file '{}': {}", to, err);
        return;
    }
}
