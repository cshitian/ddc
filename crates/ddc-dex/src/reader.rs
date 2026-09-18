//! Little-endian cursor: u1..u8 reads, LEB128, MUTF-8.

#[derive(Debug, Clone, Copy)]
pub struct Cursor<'a> {
    pub data: &'a [u8],
    pub pos: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Cursor { data, pos: 0 }
    }

    pub fn at(data: &'a [u8], pos: usize) -> Self {
        Cursor { data, pos }
    }

    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.remaining() < n {
            return None;
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Some(s)
    }

    pub fn u1(&mut self) -> Option<u8> {
        self.take(1).map(|s| s[0])
    }

    pub fn u2(&mut self) -> Option<u16> {
        self.take(2).map(|s| u16::from_le_bytes([s[0], s[1]]))
    }

    pub fn u4(&mut self) -> Option<u32> {
        self.take(4)
            .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    pub fn s4(&mut self) -> Option<i32> {
        self.u4().map(|v| v as i32)
    }

    pub fn u8v(&mut self) -> Option<u64> {
        self.take(8).map(|s| {
            let mut b = [0u8; 8];
            b.copy_from_slice(s);
            u64::from_le_bytes(b)
        })
    }

    /// Bytes from the current position, without consuming.
    pub fn peek_rest(&self) -> &'a [u8] {
        &self.data[self.pos.min(self.data.len())..]
    }

    pub fn skip(&mut self, n: usize) {
        self.pos = (self.pos + n).min(self.data.len());
    }

    pub fn read_uleb128(&mut self) -> Option<u64> {
        let mut result: u64 = 0;
        let mut shift = 0u32;
        loop {
            let b = self.u1()?;
            result |= ((b & 0x7f) as u64) << shift;
            if b & 0x80 == 0 {
                return Some(result);
            }
            shift += 7;
            if shift > 63 {
                return None;
            }
        }
    }

    pub fn read_sleb128(&mut self) -> Option<i64> {
        let mut result: i64 = 0;
        let mut shift = 0u32;
        loop {
            let b = self.u1()?;
            result |= ((b & 0x7f) as i64) << shift;
            shift += 7;
            if b & 0x80 == 0 {
                if shift < 64 && (b & 0x40) != 0 {
                    result |= -1i64 << shift;
                }
                return Some(result);
            }
            if shift > 63 {
                return None;
            }
        }
    }

    /// uleb128 whose encoding adds +1 to the stored value (NO_INDEX = 0 → -1).
    pub fn read_uleb128p1(&mut self) -> Option<i64> {
        self.read_uleb128().map(|v| v as i64 - 1)
    }

    /// Read a MUTF-8 string of `utf16_len` code units starting at `pos`
    /// (does not consume the cursor).
    pub fn read_mutf8(&self, pos: usize, utf16_len: u64) -> Option<String> {
        // Fast path: pure-ASCII (and terminating NUL) strings — the vast
        // majority of a dex's string table — decode straight through
        // `str::from_utf8`. The per-byte state machine below stays for
        // the multi-byte/edge cases.
        if let Some(nul) = self.data[pos..].iter().position(|&b| b == 0) {
            let ascii = &self.data[pos..pos + nul];
            if !ascii.is_empty() && ascii.is_ascii() {
                // ASCII bytes are valid UTF-8 by construction.
                return Some(unsafe { std::str::from_utf8_unchecked(ascii).to_string() });
            }
        }
        let mut out = String::new();
        let mut i = pos;
        let mut units = 0u64;
        // Corrupt sequences degrade to U+FFFD rather than failing the file.
        while units < utf16_len {
            if i >= self.data.len() {
                return None;
            }
            let b0 = self.data[i];
            match b0 {
                0x00 => {
                    // Encoded 0 is 0xC0 0x80; a bare NUL terminates the string.
                    break;
                }
                0x01..=0x7f => {
                    out.push(b0 as char);
                    i += 1;
                }
                0xc0..=0xdf => {
                    if i + 1 >= self.data.len() || (self.data[i + 1] & 0xc0) != 0x80 {
                        out.push('\u{fffd}');
                        i += 1;
                    } else {
                        let c = (((b0 & 0x1f) as u32) << 6) | ((self.data[i + 1] & 0x3f) as u32);
                        out.push(char::from_u32(c).unwrap_or('\u{fffd}'));
                        i += 2;
                    }
                }
                0xe0..=0xef => {
                    if i + 2 >= self.data.len()
                        || (self.data[i + 1] & 0xc0) != 0x80
                        || (self.data[i + 2] & 0xc0) != 0x80
                    {
                        out.push('\u{fffd}');
                        i += 1;
                    } else {
                        let c = (((b0 & 0x0f) as u32) << 12)
                            | (((self.data[i + 1] & 0x3f) as u32) << 6)
                            | ((self.data[i + 2] & 0x3f) as u32);
                        // Supplementary characters arrive as surrogate pairs.
                        if (0xd800..0xdc00).contains(&c) {
                            if i + 5 < self.data.len()
                                && (self.data[i + 3] & 0xf0) == 0xe0
                                && (self.data[i + 4] & 0xc0) == 0x80
                                && (self.data[i + 5] & 0xc0) == 0x80
                            {
                                let lo = (((self.data[i + 3] & 0x0f) as u32) << 12)
                                    | (((self.data[i + 4] & 0x3f) as u32) << 6)
                                    | ((self.data[i + 5] & 0x3f) as u32);
                                let cp = 0x10000 + ((c - 0xd800) << 10) + (lo - 0xdc00);
                                out.push(char::from_u32(cp).unwrap_or('\u{fffd}'));
                                i += 6;
                                units += 2;
                                continue;
                            }
                            out.push('\u{fffd}');
                            i += 3;
                        } else {
                            out.push(char::from_u32(c).unwrap_or('\u{fffd}'));
                            i += 3;
                        }
                    }
                }
                _ => {
                    out.push('\u{fffd}');
                    i += 1;
                }
            }
            units += 1;
        }
        Some(out)
    }
}

/// Format a MUTF-8 string like the DEX spec's uleb-terminated layout:
/// `utf16_len` then bytes then 0x00.
pub fn mutf8_decode(data: &[u8], utf16_len: u64) -> Option<String> {
    Cursor::new(data).read_mutf8(0, utf16_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uleb() {
        let mut c = Cursor::new(&[0x00]);
        assert_eq!(c.read_uleb128(), Some(0));
        let mut c = Cursor::new(&[0x81, 0x01]);
        assert_eq!(c.read_uleb128(), Some(129));
        let mut c = Cursor::new(&[0xff, 0xff, 0xff, 0xff, 0x0f]);
        assert_eq!(c.read_uleb128(), Some(0xffff_ffff));
    }

    #[test]
    fn sleb() {
        let mut c = Cursor::new(&[0x00]);
        assert_eq!(c.read_sleb128(), Some(0));
        let mut c = Cursor::new(&[0x7f]);
        assert_eq!(c.read_sleb128(), Some(-1));
        let mut c = Cursor::new(&[0x81, 0x7f]);
        assert_eq!(c.read_sleb128(), Some(-127));
        let mut c = Cursor::new(&[0xc0, 0xbb, 0x78]);
        assert_eq!(c.read_sleb128(), Some(-123456));
    }

    #[test]
    fn mutf8_ascii() {
        assert_eq!(mutf8_decode(b"hello\0", 5).as_deref(), Some("hello"));
    }

    #[test]
    fn mutf8_embedded_nul() {
        assert_eq!(mutf8_decode(&[0xc0, 0x80], 1).as_deref(), Some("\0"));
    }

    #[test]
    fn mutf8_supplementary() {
        // U+1F600 as a surrogate pair in MUTF-8.
        let bytes = [0xed, 0xa0, 0xbd, 0xed, 0xb8, 0x80];
        assert_eq!(mutf8_decode(&bytes, 2).as_deref(), Some("\u{1f600}"));
    }
}
