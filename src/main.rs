extern crate env_logger;
extern crate faerie;
extern crate goblin;
extern crate memmap;
extern crate object;
extern crate target_lexicon;

use std::collections::HashMap;
use std::{env, fs, process};

use faerie::{ArtifactBuilder, Decl, Link, RelocOverride};
use goblin::elf;
use object::{Object, ObjectSection, RelocationKind, SectionKind, SymbolKind};
use target_lexicon::{Architecture, BinaryFormat, Environment, OperatingSystem, Triple, Vendor};

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
    let file = match object::File::parse(&*file) {
        Ok(file) => file,
        Err(err) => {
            println!("Failed to parse file '{}': {}", from, err);
            return;
        }
    };

    let target = Triple {
        architecture: Architecture::X86_64,
        vendor: Vendor::Unknown,
        operating_system: OperatingSystem::Unknown,
        environment: Environment::Unknown,
        binary_format: BinaryFormat::Elf,
    };

    let mut artifact = ArtifactBuilder::new(target).name(to.to_string()).finish();

    for symbol in file.symbols() {
        let name = match symbol.name() {
            Some("") | None => continue,
            Some(name) => name,
        };

        let decl = match symbol.kind() {
            SymbolKind::File => {
                // TODO: use name for ArtifactBuilder
                continue;
            }
            SymbolKind::Text => {
                if symbol.is_undefined() {
                    Decl::FunctionImport
                } else {
                    Decl::Function {
                        global: symbol.is_global(),
                    }
                }
            }
            SymbolKind::Data => {
                if symbol.is_undefined() {
                    Decl::DataImport
                } else {
                    // TODO: writable
                    Decl::Data {
                        global: symbol.is_global(),
                        writable: true,
                    }
                }
            }
            _ => {
                if symbol.is_undefined() {
                    // TODO: How do we tell between function and data?
                    Decl::FunctionImport
                } else {
                    println!("Unsupported symbol: {:?}", symbol);
                    return;
                }
            }
        };

        artifact.declare(name, decl).unwrap();
        if !symbol.is_undefined() {
            let mut data = symbol.data().to_vec();
            data.resize(symbol.size() as usize, 0);
            artifact.define(name, data).unwrap();
        }
    }

    for section in file.sections() {
        if let Some(name) = section.name() {
            if name.starts_with(".debug_") {
                artifact.declare(name, Decl::DebugSection).unwrap();
                artifact
                    .define(name, section.uncompressed_data().into_owned())
                    .unwrap();
            }
        }
    }

    let mut symbols = HashMap::new();
    for section in file.sections() {
        let mut section_symbols: Vec<_> = section.symbols().collect();
        section_symbols.sort_by_key(|s| s.address());
        symbols.insert(section.id(), section_symbols);
    }

    for section in file.sections() {
        match section.kind() {
            SectionKind::Text | SectionKind::Data | SectionKind::ReadOnlyData => {}
            SectionKind::Unknown => {
                if section.name().map(|name| name.starts_with(".debug_")) != Some(true) {
                    continue;
                }
            }
            _ => continue,
        }
        if section.name() == Some(".eh_frame") {
            // Not supported by faerie yet.
            continue;
        }
        let section_symbols = symbols.get(&section.id()).unwrap();
        for (offset, relocation) in section.relocations() {
            //println!("\nrelocation: {:x} {:?}", offset, relocation);
            let address = section.address() + offset;
            let from_symbol = section_symbols
                .binary_search_by(|s| s.cmp_address(address))
                .map(|index| &section_symbols[index]);
            //println!("from_symbol {:?}", from_symbol);
            let from = match from_symbol {
                Ok(s) => s.name().unwrap(),
                Err(_) => section.name().unwrap(),
            };
            let at = match from_symbol {
                Ok(s) => address - s.address(),
                Err(_) => offset,
            };

            let mut to_symbol = file.symbol_by_index(relocation.symbol()).unwrap();
            //println!("to_symbol {:?}", to_symbol);
            let to = &if to_symbol.kind() == SymbolKind::Section {
                let to_section_id = to_symbol.section_id().unwrap();
                let to_section = file.section_by_id(to_section_id).unwrap();
                let to_symbols = symbols.get(&to_section_id).unwrap();
                let to_symbol = to_symbols
                    .binary_search_by(|s| s.cmp_address(to_symbol.address()))
                    .map(|index| &to_symbols[index]);
                match to_symbol {
                    Ok(s) => s.name().unwrap(),
                    Err(_) => to_section.name().unwrap(),
                }.to_string()
            } else {
                to_symbol.name().unwrap().to_string()
            };

            assert!(!relocation.has_implicit_addend());
            let addend = relocation.addend() as i32;
            let reloc = match relocation.kind() {
                RelocationKind::Direct64 => elf::reloc::R_X86_64_64,
                RelocationKind::Direct32 => elf::reloc::R_X86_64_32,
                RelocationKind::DirectSigned32 => elf::reloc::R_X86_64_32S,
                RelocationKind::Other(kind) => kind,
            };
            if let Err(_err) =
                artifact.link_with(Link { from, to, at }, RelocOverride { reloc, addend })
            {
                //println!("Link failed: {} {} 0x{:x} 0x{:x} 0x{:x}: {}", from, to, at, reloc, addend, _err);
            } else {
                //println!("Link ok: {} {} 0x{:x} 0x{:x} 0x{:x}", from, to, at, reloc, addend);
            }
        }
    }

    let file = match fs::File::create(&to) {
        Ok(file) => file,
        Err(err) => {
            println!("Failed to create file '{}': {}", to, err);
            return;
        }
    };
    if let Err(err) = artifact.write(file) {
        println!("Failed to write file '{}': {}", to, err);
        return;
    }
}
