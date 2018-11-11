use std::collections::HashMap;

use object::{Object, ObjectSection, Symbol, SymbolKind};

pub struct SymbolMap<'data> {
    symbols: HashMap<usize, Vec<Symbol<'data>>>,
}

impl<'data> SymbolMap<'data> {
    pub fn new(file: &object::File<'data>) -> Self {
        let mut symbols = HashMap::new();
        for section in file.sections() {
            let mut section_symbols: Vec<_> = section.symbols().collect();
            section_symbols.sort_by_key(|s| s.address());
            symbols.insert(section.id(), section_symbols);
        }
        SymbolMap { symbols }
    }

    pub fn lookup_symbol_offset(
        &self,
        file: &object::File,
        symbol: &object::Symbol,
        offset: u64,
    ) -> (String, u64) {
        if symbol.kind() == SymbolKind::Section {
            let section_id = symbol.section_id().unwrap();
            let section = file.section_by_id(section_id).unwrap();
            self.lookup_section_offset(&section, offset)
        } else {
            (symbol.name().unwrap().to_string(), offset)
        }
    }

    pub fn lookup_section_offset(&self, section: &object::Section, offset: u64) -> (String, u64) {
        let section_symbols = self.symbols.get(&section.id()).unwrap();
        let address = section.address() + offset;
        let symbol = section_symbols
            .binary_search_by(|s| s.cmp_address(address))
            .map(|index| &section_symbols[index]);
        match symbol {
            Ok(s) => (s.name().unwrap().to_string(), address - s.address()),
            Err(_) => (section.name().unwrap().to_string(), offset),
        }
    }
}
