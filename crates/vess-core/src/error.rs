//! Decoding failures. Every rejection is a distinct, non-attributable error: a malformed
//! input never panics and never allocates more than the input already contains.

use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecError {
    /// Input ended before the field was complete.
    Truncated,
    /// Bytes remained after the last field of a fully delimited object.
    TrailingBytes,
    /// A length prefix exceeded the maximum permitted for this context.
    LengthTooLarge,
    /// A field held a value outside its permitted range.
    InvalidValue,
    /// Version or tag byte not supported by protocol version 1.
    UnknownVersion,
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            CodecError::Truncated => "truncated input",
            CodecError::TrailingBytes => "trailing bytes",
            CodecError::LengthTooLarge => "length prefix exceeds context maximum",
            CodecError::InvalidValue => "invalid field value",
            CodecError::UnknownVersion => "unsupported version or tag",
        };
        f.write_str(s)
    }
}

impl std::error::Error for CodecError {}
