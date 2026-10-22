use std::time::Duration;

/// Delay before retry number `attempts + 1`; `None` once retries are exhausted.
pub fn backoff(attempts: u32) -> Option<Duration> {
    let mins = match attempts {
        0 => 1,
        1 => 5,
        2 => 15,
        3 => 60,
        _ => return None,
    };
    Some(Duration::from_secs(mins * 60))
}
