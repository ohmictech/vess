//! A tiny leveled logger.
//!
//! A node that cannot be observed cannot be operated, and this crate deliberately has no logging
//! dependency. Records go to stderr as
//! `2026-11-10T17:00:00.123Z LEVEL target: message`, filtered by the `VESS_LOG` environment variable
//! (`error`, `warn`, `info`, `debug`, or `off`; default `info`). Command output that is part of a
//! CLI contract stays on stdout via `println!` and is not a log record.

use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Error = 1,
    Warn = 2,
    Info = 3,
    Debug = 4,
}

impl Level {
    fn label(self) -> &'static str {
        match self {
            Level::Error => "ERROR",
            Level::Warn => "WARN",
            Level::Info => "INFO",
            Level::Debug => "DEBUG",
        }
    }

    fn parse(value: &str) -> Option<u8> {
        match value.trim().to_ascii_lowercase().as_str() {
            "off" | "none" => Some(0),
            "error" => Some(Level::Error as u8),
            "warn" | "warning" => Some(Level::Warn as u8),
            "info" => Some(Level::Info as u8),
            "debug" | "trace" => Some(Level::Debug as u8),
            _ => None,
        }
    }
}

static THRESHOLD: AtomicU8 = AtomicU8::new(Level::Info as u8);

/// Read `VESS_LOG` once. Safe to call more than once; the last call wins.
pub fn init() {
    let level = std::env::var("VESS_LOG")
        .ok()
        .and_then(|value| Level::parse(&value))
        .unwrap_or(Level::Info as u8);
    THRESHOLD.store(level, Ordering::Relaxed);
}

pub fn enabled(level: Level) -> bool {
    (level as u8) <= THRESHOLD.load(Ordering::Relaxed)
}

/// Emit one record. `target` is normally a module or subsystem name.
pub fn record(level: Level, target: &str, message: &str) {
    if !enabled(level) {
        return;
    }
    eprintln!("{} {} {}: {}", timestamp(), level.label(), target, message);
}

/// RFC 3339 UTC with milliseconds, from the system clock. No external crate.
pub fn timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let seconds = now.as_secs();
    let millis = now.subsec_millis();

    let days = (seconds / 86_400) as i64;
    let mut rem = seconds % 86_400;
    let hour = rem / 3_600;
    rem %= 3_600;
    let minute = rem / 60;
    let second = rem % 60;

    // Civil date from days since the Unix epoch (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

#[macro_export]
macro_rules! log_error {
    ($target:expr, $($arg:tt)*) => {
        $crate::log::record($crate::log::Level::Error, $target, &format!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_warn {
    ($target:expr, $($arg:tt)*) => {
        $crate::log::record($crate::log::Level::Warn, $target, &format!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_info {
    ($target:expr, $($arg:tt)*) => {
        $crate::log::record($crate::log::Level::Info, $target, &format!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_debug {
    ($target:expr, $($arg:tt)*) => {
        $crate::log::record($crate::log::Level::Debug, $target, &format!($($arg)*))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_parse_and_order() {
        assert_eq!(Level::parse("error"), Some(Level::Error as u8));
        assert_eq!(Level::parse("WARN"), Some(Level::Warn as u8));
        assert_eq!(Level::parse(" info "), Some(Level::Info as u8));
        assert_eq!(Level::parse("debug"), Some(Level::Debug as u8));
        assert_eq!(Level::parse("off"), Some(0));
        assert_eq!(Level::parse("chatty"), None);
        assert!(Level::Error < Level::Warn);
        assert!(Level::Warn < Level::Info);
        assert!(Level::Info < Level::Debug);
    }

    #[test]
    fn timestamps_are_rfc3339_utc() {
        let stamp = timestamp();
        assert_eq!(stamp.len(), 24, "{stamp}");
        assert!(stamp.ends_with('Z'), "{stamp}");
        assert_eq!(&stamp[4..5], "-");
        assert_eq!(&stamp[10..11], "T");
        assert_eq!(&stamp[19..20], ".");
        // Sanity: the year is in this century, so the civil-date maths is not off by an era.
        let year: i32 = stamp[..4].parse().unwrap();
        assert!((2024..2200).contains(&year), "{stamp}");
    }

    #[test]
    fn records_respect_the_threshold() {
        // Not asserting on stderr, only that the filter is wired the way the field expects.
        THRESHOLD.store(Level::Warn as u8, Ordering::Relaxed);
        assert!(enabled(Level::Error));
        assert!(enabled(Level::Warn));
        assert!(!enabled(Level::Info));
        assert!(!enabled(Level::Debug));
        THRESHOLD.store(Level::Info as u8, Ordering::Relaxed);
    }
}
