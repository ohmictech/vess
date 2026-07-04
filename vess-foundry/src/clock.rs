//! Simple epoch clock — 24-hour windows since genesis.
//!
//! One epoch = 86400 seconds. The current epoch number is deterministic
//! from wall time. Useful for time-locks, mining epochs, and bill expiry.

/// One epoch in seconds.
pub const EPOCH_SECS: u64 = 86400;

/// Genesis timestamp: 2026-01-01T00:00:00Z in Unix seconds.
pub const EPOCH_GENESIS: u64 = 1767225600;

/// Current epoch number.
pub fn current_epoch() -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    now.saturating_sub(EPOCH_GENESIS) / EPOCH_SECS
}

/// Start time of the given epoch, in Unix seconds.
pub fn epoch_start(epoch: u64) -> u64 {
    EPOCH_GENESIS + epoch * EPOCH_SECS
}

/// End time of the given epoch, in Unix seconds.
pub fn epoch_end(epoch: u64) -> u64 {
    epoch_start(epoch) + EPOCH_SECS
}

/// Approximate epochs in one year.
pub const EPOCHS_PER_YEAR: u64 = 365;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_math() {
        assert_eq!(epoch_start(0), EPOCH_GENESIS);
        assert_eq!(epoch_end(0), EPOCH_GENESIS + EPOCH_SECS);
        assert_eq!(epoch_start(1), EPOCH_GENESIS + EPOCH_SECS);
    }

    #[test]
    fn current_epoch_is_reasonable() {
        let e = current_epoch();
        assert!(e > 0);
        assert!(e < 100_000);
    }
}
