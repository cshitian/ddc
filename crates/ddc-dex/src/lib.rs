//! ddc-dex — DEX container parsing and Dalvik instruction decoding.
//!
//! Pure, allocation-light, read-only access to a `.dex` image:
//! * [`DexFile`] walks the header, id tables, class defs, code items and
//!   annotations lazily (indices resolved on demand, strings cached).
//! * [`insn`] decodes Dalvik instructions in all formats plus the three
//!   payload pseudo-instructions.
//!
//! The decompiler front-end lives in `ddc-dec`; this crate only turns bytes
//! into a structured view, never fails hard on malformed regions (accessors
//! return `None` / `u32::MAX` sentinels).

pub mod annotations;
pub mod code;
pub mod insn;
pub mod reader;

pub use code::{CatchHandler, CodeItem, TryItem};
pub use file::{ClassData, EncodedField, EncodedMethod};

mod file;
pub use file::{ClassDef, DexFile, FieldId, MethodId, ProtoId, NO_INDEX};

pub const DEX_HEADER_SIZE: usize = 0x70;
