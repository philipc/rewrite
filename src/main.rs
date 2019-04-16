extern crate env_logger;
extern crate faerie;
extern crate gimli;
extern crate goblin;
extern crate memmap;
extern crate object;
extern crate target_lexicon;

use std::{env, fs, process};

use faerie::{Artifact, ArtifactBuilder, Decl, Link, Reloc};
use goblin::elf;
use object::{Object, ObjectSection, RelocationKind, SectionKind, SymbolKind};
use target_lexicon::{Architecture, BinaryFormat, Environment, OperatingSystem, Triple, Vendor};

mod dwarf;
use dwarf::*;

mod symbol;
use symbol::*;

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

    assert_eq!(file.machine(), object::Machine::X86_64);
    let target = Triple {
        architecture: Architecture::X86_64,
        vendor: Vendor::Unknown,
        operating_system: OperatingSystem::Unknown,
        environment: Environment::Unknown,
        binary_format: BinaryFormat::Elf,
    };

    let mut artifact = ArtifactBuilder::new(target).name(to.to_string()).finish();

    let symbols = SymbolMap::new(&file);

    rewrite_symbols(&file, &mut artifact);
    rewrite_dwarf(&file, &mut artifact, &symbols);
    rewrite_relocations(&file, &mut artifact, &symbols);

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

fn rewrite_symbols(file: &object::File, artifact: &mut Artifact) {
    for (_, symbol) in file.symbols() {
        let name = match symbol.name() {
            Some("") | None => continue,
            Some(name) => name,
        };

        let decl: Decl = match symbol.kind() {
            SymbolKind::File => {
                // TODO: use name for ArtifactBuilder
                continue;
            }
            SymbolKind::Text => {
                if symbol.is_undefined() {
                    Decl::function_import().into()
                } else {
                    // TODO: weak symbols
                    if symbol.is_global() {
                        Decl::function().global().into()
                    } else {
                        Decl::function().into()
                    }
                }
            }
            SymbolKind::Data => {
                if symbol.is_undefined() {
                    Decl::data_import().into()
                } else {
                    // TODO: writable, weak
                    if symbol.is_global() {
                        Decl::data().global().writable().into()
                    } else {
                        Decl::data().writable().into()
                    }
                }
            }
            _ => {
                if symbol.is_undefined() {
                    // TODO: How do we tell between function and data?
                    Decl::function_import().into()
                } else {
                    println!("Unsupported symbol: {:?}", symbol);
                    continue;
                }
            }
        };

        artifact.declare(name, decl).unwrap();
        if !symbol.is_undefined() {
            let mut data = file.symbol_data(&symbol).unwrap().to_vec();
            data.resize(symbol.size() as usize, 0);
            artifact.define(name, data).unwrap();
        }
    }
}

fn rewrite_relocations(file: &object::File, artifact: &mut Artifact, symbols: &SymbolMap) {
    for section in file.sections() {
        match section.kind() {
            SectionKind::Text | SectionKind::Data | SectionKind::ReadOnlyData => {}
            SectionKind::Unknown => {
                if !is_copy_dwarf_section(&section) {
                    continue;
                }
            }
            _ => continue,
        }
        if section.name() == Some(".eh_frame") {
            // Not supported by faerie yet.
            continue;
        }
        for (offset, relocation) in section.relocations() {
            //println!("\nrelocation: {:x} {:?}", offset, relocation);
            let (from, at) = symbols.lookup_section_offset(&section, offset);

            let mut to_symbol = file.symbol_by_index(relocation.symbol()).unwrap();
            //println!("to_symbol {:?}", to_symbol);
            assert!(!relocation.has_implicit_addend());
            let addend = relocation.addend() as u64;
            let (to, addend) = symbols.lookup_symbol_offset(&file, &to_symbol, addend);

            let reloc = match relocation.kind() {
                RelocationKind::Direct64 => elf::reloc::R_X86_64_64,
                RelocationKind::Direct32 => elf::reloc::R_X86_64_32,
                RelocationKind::DirectSigned32 => elf::reloc::R_X86_64_32S,
                RelocationKind::Other(kind) => kind,
            };
            if let Err(_err) = artifact.link_with(
                Link {
                    from: &from,
                    to: &to,
                    at,
                },
                Reloc::Raw {
                    reloc,
                    addend: addend as i32,
                },
            ) {
                //println!("Link failed: {} {} 0x{:x} 0x{:x} 0x{:x}: {}", from, to, at, reloc, addend, _err);
            } else {
                //println!("Link ok: {} {} 0x{:x} 0x{:x} 0x{:x}", from, to, at, reloc, addend);
            }
        }
    }
}
