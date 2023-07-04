use std::fmt::{self, Display};

use syn::{Ident, Path};

/// A type to represent the name of a macro attribute.
#[derive(Copy, Clone)]
pub(crate) struct Symbol(&'static str);

// Attributes
pub(crate) const NO_MAIN: Symbol = Symbol("no_main");
pub(crate) const OCKAM_CRATE: Symbol = Symbol("crate");
pub(crate) const TIMEOUT_MS: Symbol = Symbol("timeout");
pub(crate) const NO_LOGGING: Symbol = Symbol("no_logging");

// Derive's helper attributes
pub(crate) const ASYNC_TRY_CLONE: Symbol = Symbol("async_try_clone");

impl PartialEq<Symbol> for Ident {
    fn eq(&self, word: &Symbol) -> bool {
        self == word.0
    }
}

impl<'a> PartialEq<Symbol> for &'a Ident {
    fn eq(&self, word: &Symbol) -> bool {
        *self == word.0
    }
}

impl PartialEq<Symbol> for Path {
    fn eq(&self, word: &Symbol) -> bool {
        self.is_ident(word.0)
    }
}

impl<'a> PartialEq<Symbol> for &'a Path {
    fn eq(&self, word: &Symbol) -> bool {
        self.is_ident(word.0)
    }
}

impl Display for Symbol {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str(self.0)
    }
}
