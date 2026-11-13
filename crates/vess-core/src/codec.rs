//! The single canonical binary codec. Every integer is unsigned, fixed-width, big-endian.
//! Decoding never allocates before validating a length against the remaining input.

use crate::error::CodecError;

#[derive(Default, Debug, Clone)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Writer { buf: Vec::new() }
    }

    pub fn with_capacity(cap: usize) -> Self {
        Writer {
            buf: Vec::with_capacity(cap),
        }
    }

    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn bytes(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }

    pub fn fixed<const N: usize>(&mut self, b: &[u8; N]) {
        self.buf.extend_from_slice(b);
    }

    /// `u32` length prefix followed by the bytes. Callers must enforce the context maximum
    /// before writing; `var_bytes` itself only rejects lengths that cannot be represented.
    pub fn var_bytes(&mut self, b: &[u8]) -> Result<(), CodecError> {
        let len = u32::try_from(b.len()).map_err(|_| CodecError::LengthTooLarge)?;
        self.u32(len);
        self.bytes(b);
        Ok(())
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        if n > self.remaining() {
            return Err(CodecError::Truncated);
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    pub fn u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.take(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16, CodecError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub fn u32(&mut self) -> Result<u32, CodecError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn u64(&mut self) -> Result<u64, CodecError> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_be_bytes(a))
    }

    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        self.take(n)
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        let b = self.take(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(b);
        Ok(out)
    }

    pub fn var_bytes(&mut self, max: usize) -> Result<&'a [u8], CodecError> {
        let len = self.u32()? as usize;
        if len > max {
            return Err(CodecError::LengthTooLarge);
        }
        self.take(len)
    }

    /// Reject any bytes after the last field of a fully delimited object.
    pub fn finish(self) -> Result<(), CodecError> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(CodecError::TrailingBytes)
        }
    }
}

/// Encode into a fresh buffer.
pub trait Encode {
    fn encode(&self, w: &mut Writer);
}

/// Decode from a reader positioned at the start of the object.
pub trait Decode: Sized {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError>;
}

/// Convenience: canonical bytes of an encodable value.
pub fn to_bytes<T: Encode>(v: &T) -> Vec<u8> {
    let mut w = Writer::new();
    v.encode(&mut w);
    w.into_vec()
}

/// Convenience: decode a complete object, rejecting trailing bytes.
pub fn from_bytes<T: Decode>(bytes: &[u8]) -> Result<T, CodecError> {
    let mut r = Reader::new(bytes);
    let v = T::decode(&mut r)?;
    r.finish()?;
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_are_big_endian() {
        let mut w = Writer::new();
        w.u16(0x0102);
        w.u32(0x0304_0506);
        w.u64(0x0708_090a_0b0c_0d0e);
        assert_eq!(
            w.as_slice(),
            &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]
        );
    }

    #[test]
    fn truncation_is_rejected() {
        let mut r = Reader::new(&[0, 1, 2]);
        assert_eq!(r.u32(), Err(CodecError::Truncated));
        // A failed read consumes nothing.
        assert_eq!(r.remaining(), 3);
    }

    #[test]
    fn oversized_length_prefix_is_rejected_before_reading() {
        let mut w = Writer::new();
        w.u32(1_000_000);
        w.bytes(b"short");
        let mut r = Reader::new(w.as_slice());
        assert_eq!(r.var_bytes(16), Err(CodecError::LengthTooLarge));
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut r = Reader::new(&[1, 2]);
        assert_eq!(r.u8(), Ok(1));
        assert_eq!(r.finish(), Err(CodecError::TrailingBytes));
    }

    #[test]
    fn var_bytes_roundtrip() {
        let mut w = Writer::new();
        w.var_bytes(b"hello").unwrap();
        assert_eq!(w.as_slice(), &[0, 0, 0, 5, b'h', b'e', b'l', b'l', b'o']);
        let mut r = Reader::new(w.as_slice());
        assert_eq!(r.var_bytes(5).unwrap(), b"hello");
        assert_eq!(r.finish(), Ok(()));
    }
}
