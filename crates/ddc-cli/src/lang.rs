//! Bilingual CLI messages. Chinese when the environment asks for it —
//! `DDC_LANG` (explicit override) beats `LC_ALL` beats `LC_MESSAGES` beats
//! `LANG`, any value starting with `zh` (zh, zh_CN, zh_TW...) selects
//! Chinese; everything else falls back to English.

use std::sync::OnceLock;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lang {
    En,
    Zh,
}

impl Lang {
    fn detect() -> Lang {
        for var in ["DDC_LANG", "LC_ALL", "LC_MESSAGES", "LANG"] {
            let Ok(v) = std::env::var(var) else { continue };
            let v = v.to_ascii_lowercase();
            if v.starts_with("zh") {
                return Lang::Zh;
            }
            // DDC_LANG is an explicit choice: `en` short-circuits even if
            // LANG would have said zh.
            if var == "DDC_LANG" && v.starts_with("en") {
                return Lang::En;
            }
        }
        Lang::En
    }
}

/// The process-wide language, resolved once.
pub(crate) fn lang() -> Lang {
    static LANG: OnceLock<Lang> = OnceLock::new();
    *LANG.get_or_init(Lang::detect)
}

/// Pick one of two static strings by language.
pub(crate) fn pick(en: &'static str, zh: &'static str) -> &'static str {
    match lang() {
        Lang::En => en,
        Lang::Zh => zh,
    }
}

/// `bi!("english", "中文")` → one of the literals.
macro_rules! bi {
    ($en:expr, $zh:expr) => {
        $crate::lang::pick($en, $zh)
    };
}

/// `bif!("{} files", "{} 个文件"; n)` → `format!` of the chosen literal.
/// Both format strings share one argument list — use {0}/{1} positional
/// slots when the argument order differs between the two languages.
/// format! needs a LITERAL first argument, so each arm formats its own
/// captured literal directly (an expr capture would be rejected).
macro_rules! bif {
    ($en:literal, $zh:literal) => {
        $crate::lang::pick($en, $zh)
    };
    ($en:literal, $zh:literal; $($arg:tt)*) => {
        match $crate::lang::lang() {
            $crate::lang::Lang::Zh => format!($zh, $($arg)*),
            $crate::lang::Lang::En => format!($en, $($arg)*),
        }
    };
}

pub(crate) use bi;
pub(crate) use bif;
