//! `code_item`: register frame, insns, try table and catch handlers.

use std::collections::HashMap;

use crate::insn::{decode_all, Insn, Payload};
use crate::reader::Cursor;

/// One decoded try region.
#[derive(Debug, Clone)]
pub struct TryItem {
    /// First code unit covered (inclusive).
    pub start_addr: u32,
    /// Number of 16-bit code units covered.
    pub insn_count: u32,
    /// Index into [`CodeItem::handlers`].
    pub handler_idx: usize,
}

/// One `encoded_catch_handler`.
#[derive(Debug, Clone)]
pub struct CatchHandler {
    /// `(type id, handler address)` pairs, in priority order.
    pub catches: Vec<(u32, u32)>,
    /// Catch-all (`finally`) handler address.
    pub catch_all: Option<u32>,
}

/// A decoded `code_item`.
#[derive(Debug, Clone)]
pub struct CodeItem {
    pub registers_size: u16,
    /// Incoming argument registers (the LAST `ins_size` registers).
    pub ins_size: u16,
    pub outs_size: u16,
    pub debug_info_off: u32,
    /// Linearly decoded instructions (payload bodies are NOT included —
    /// they live in `payloads`).
    pub insns: Vec<Insn>,
    /// Payload pseudo-instructions keyed by their code-unit offset.
    pub payloads: HashMap<u32, Payload>,
    pub tries: Vec<TryItem>,
    pub handlers: Vec<CatchHandler>,
}

impl CodeItem {
    pub fn parse(data: &[u8], off: usize) -> Option<CodeItem> {
        let mut c = Cursor::at(data, off);
        let registers_size = c.u2()?;
        let ins_size = c.u2()?;
        let outs_size = c.u2()?;
        let tries_size = c.u2()?;
        let debug_info_off = c.u4()?;
        let insns_size = c.u4()? as usize; // in 16-bit code units
        let insns_off = c.pos;
        if insns_off + 2 * insns_size > data.len() {
            return None;
        }
        let insns_end = insns_off + 2 * insns_size;
        let (insns, payloads) = decode_all(&data[insns_off..insns_end]);

        // Optional 4-byte alignment padding before the try table.
        let mut p = insns_end;
        if tries_size != 0 && insns_size % 2 == 1 {
            p += 2;
        }

        let mut tries = Vec::with_capacity(tries_size as usize);
        let mut c = Cursor::at(data, p);
        for _ in 0..tries_size {
            let start_addr = c.u4()?;
            let insn_count = c.u2()? as u32;
            // Raw byte offset from the start of the handler list; resolved
            // below once the list has been walked.
            let handler_off = c.u2()? as usize;
            tries.push(TryItem {
                start_addr,
                insn_count,
                handler_idx: handler_off,
            });
        }

        // encoded_catch_handler_list: uleb size, then handlers back to
        // back. Present ONLY when tries exist (spec 8.3.1): the
        // unconditional read used to consume whatever bytes followed the
        // item — harmless inside a live image, fatal for exact-sized
        // snapshot slices (parse bailed at the bound → accessor inlining
        // silently off corpus-wide → 187 un-inlined `g.l.i(..)` shadow
        // refs in reqable's flutter g.java alone).
        let mut handlers: Vec<CatchHandler> = Vec::new();
        if tries_size != 0 {
            let list_off = c.pos;
            let n_handlers = c.read_uleb128()? as usize;
            let uleb_len = c.pos - list_off;
            handlers.reserve(n_handlers);
            // handler byte offset (from list start) → handler index.
            let mut idx_by_off: HashMap<usize, usize> = HashMap::new();
            for _ in 0..n_handlers {
                let hoff = c.pos - list_off;
                let h = Self::parse_handler(c)?;
                idx_by_off.insert(hoff, handlers.len());
                handlers.push(h);
            }

            // Resolve each try's handler_off. The spec's offsets are from
            // the list start (the uleb size included in the offset space);
            // some writers count from after it — accept both, then the
            // first handler.
            for t in tries.iter_mut() {
                let raw = t.handler_idx;
                t.handler_idx = idx_by_off
                    .get(&raw)
                    .or_else(|| idx_by_off.get(&(raw + uleb_len)))
                    .or_else(|| idx_by_off.get(&raw.saturating_sub(uleb_len)))
                    .copied()
                    .unwrap_or(0);
            }
        }

        Some(CodeItem {
            registers_size,
            ins_size,
            outs_size,
            debug_info_off,
            insns,
            payloads,
            tries,
            handlers,
        })
    }

    fn parse_handler(mut c: Cursor<'_>) -> Option<CatchHandler> {
        let sz = c.read_sleb128()?;
        let mut h = CatchHandler {
            catches: Vec::new(),
            catch_all: None,
        };
        if sz != 0 {
            for _ in 0..sz.unsigned_abs() {
                let ty = c.read_uleb128()? as u32;
                let addr = c.read_uleb128()? as u32;
                h.catches.push((ty, addr));
            }
        }
        if sz <= 0 {
            let addr = c.read_uleb128()? as u32;
            h.catch_all = Some(addr);
        }
        Some(h)
    }

    /// Handler for a try item (index-resolved, tolerating out-of-range).
    pub fn handler_of(&self, t: &TryItem) -> Option<&CatchHandler> {
        self.handlers.get(t.handler_idx)
    }
}
