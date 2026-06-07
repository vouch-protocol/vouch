//! Minimal, dependency-free ISO-8601 handling for the protocol's timestamps.
//!
//! Vouch timestamps are always "YYYY-MM-DDTHH:MM:SSZ" (the SDK strips
//! milliseconds and always uses Zulu). This parser converts such an instant to
//! a Unix epoch second so temporal validity can be checked without pulling a
//! datetime crate into the WASM build. A trailing fractional part and an
//! explicit numeric offset (+HH:MM / -HH:MM) are tolerated.

use crate::error::{CoreError, Result};

/// Parse an ISO-8601 instant to Unix epoch seconds (UTC).
///
/// Operates entirely on bytes and validates every position, so malformed or
/// non-ASCII input (which is attacker-controlled when verifying a credential)
/// returns an error rather than panicking on a string-slice boundary.
pub fn iso_to_epoch_seconds(s: &str) -> Result<i64> {
    let b = s.as_bytes();
    let bad = || CoreError::Json(format!("invalid ISO-8601 timestamp: {s:?}"));
    if b.len() < 19 {
        return Err(bad());
    }

    // Parse `len` ASCII digits at byte offset `i`.
    let num = |i: usize, len: usize| -> Result<i64> {
        let mut v: i64 = 0;
        for k in i..i + len {
            let c = b[k];
            if !c.is_ascii_digit() {
                return Err(bad());
            }
            v = v * 10 + i64::from(c - b'0');
        }
        Ok(v)
    };

    if b[4] != b'-'
        || b[7] != b'-'
        || (b[10] != b'T' && b[10] != b't')
        || b[13] != b':'
        || b[16] != b':'
    {
        return Err(bad());
    }
    let year = num(0, 4)?;
    let month = num(5, 2)?;
    let day = num(8, 2)?;
    let hour = num(11, 2)?;
    let minute = num(14, 2)?;
    let second = num(17, 2)?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return Err(bad());
    }

    // Optional trailing fraction (".ddd") and timezone (Z or +/-HH:MM), all ASCII.
    let mut j = 19usize;
    if j < b.len() && b[j] == b'.' {
        j += 1;
        while j < b.len() && b[j].is_ascii_digit() {
            j += 1;
        }
    }
    let mut offset_seconds: i64 = 0;
    if j < b.len() {
        match b[j] {
            b'Z' | b'z' => offset_seconds = 0,
            b'+' | b'-' => {
                if j + 6 > b.len() || b[j + 3] != b':' {
                    return Err(bad());
                }
                let oh = num(j + 1, 2)?;
                let om = num(j + 4, 2)?;
                if oh > 23 || om > 59 {
                    return Err(bad());
                }
                let mag = oh * 3600 + om * 60;
                offset_seconds = if b[j] == b'+' { mag } else { -mag };
            }
            _ => return Err(bad()),
        }
    }

    let days = days_from_civil(year, month, day);
    let local = days * 86400 + hour * 3600 + minute * 60 + second;
    Ok(local - offset_seconds)
}

/// Days since the Unix epoch (1970-01-01) for a civil date.
/// Howard Hinnant's algorithm; valid for the full proleptic Gregorian range.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_known_instants() {
        assert_eq!(iso_to_epoch_seconds("1970-01-01T00:00:00Z").unwrap(), 0);
        // 2026-04-26T10:00:00Z
        assert_eq!(iso_to_epoch_seconds("2026-04-26T10:00:00Z").unwrap(), 1777197600);
    }

    #[test]
    fn window_ordering() {
        let a = iso_to_epoch_seconds("2026-04-26T10:00:00Z").unwrap();
        let b = iso_to_epoch_seconds("2026-04-26T10:05:00Z").unwrap();
        assert_eq!(b - a, 300);
    }

    #[test]
    fn rejects_malformed_without_panic() {
        // Including a multi-byte UTF-8 char in the date positions, which used to
        // panic on a string-slice boundary.
        for s in [
            "",
            "garbage",
            "2026-13-99T10:00:00Z",
            "20\u{00e9}6-04-26T10:00:00Z",
            "2026-04-26 10:00:00",
            "2026-04-26T10:0",
            "2026-04-26T25:00:00Z",
            "2026-04-26T10:00:00+9999",
        ] {
            assert!(iso_to_epoch_seconds(s).is_err(), "{s:?} should error");
        }
    }

    #[test]
    fn handles_offset_and_fraction() {
        let z = iso_to_epoch_seconds("2026-04-26T10:00:00Z").unwrap();
        assert_eq!(iso_to_epoch_seconds("2026-04-26T10:00:00.250Z").unwrap(), z);
        assert_eq!(iso_to_epoch_seconds("2026-04-26T12:00:00+02:00").unwrap(), z);
    }
}
