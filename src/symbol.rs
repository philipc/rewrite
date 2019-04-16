use object::{Object, ObjectSection, Symbol, SymbolKind};

pub struct SymbolMap<'data> {
    symbols: Vec<Symbol<'data>>,
}

impl<'data> SymbolMap<'data> {
    pub fn new(file: &object::File<'data>) -> Self {
        let mut symbols = file
            .symbols()
            .map(|(_, s)| s)
            .filter(|s| s.section_index().is_some())
            .collect::<Vec<_>>();
        symbols.sort_by_key(|s| s.address());
        SymbolMap { symbols }
    }

    pub fn lookup_symbol_offset(
        &self,
        file: &object::File,
        symbol: &object::Symbol,
        offset: u64,
    ) -> (String, u64) {
        if symbol.kind() == SymbolKind::Section {
            let section_id = symbol.section_index().unwrap();
            let section = file.section_by_index(section_id).unwrap();
            self.lookup_section_offset(&section, offset)
        } else {
            (symbol.name().unwrap().to_string(), offset)
        }
    }

    pub fn lookup_section_offset(&self, section: &object::Section, offset: u64) -> (String, u64) {
        let address = section.address() + offset;
        let cmp_address = |symbol: &object::Symbol| {
            if address < symbol.address() {
                std::cmp::Ordering::Greater
            } else if address < symbol.address() + symbol.size() {
                std::cmp::Ordering::Equal
            } else {
                std::cmp::Ordering::Less
            }
        };
        let symbol = self
            .symbols
            .binary_search_by(cmp_address)
            .map(|index| &self.symbols[index]);
        if let Ok(s) = symbol {
            if s.section_index() == Some(section.index()) {
                return (s.name().unwrap().to_string(), address - s.address());
            }
        }
        (section.name().unwrap().to_string(), offset)
    }
}
