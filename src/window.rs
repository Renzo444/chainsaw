//! Relative time windows, such as "the last 24 hours", for narrowing an investigation.

use chrono::{DateTime, Duration, Local, NaiveDateTime, TimeZone, Utc};
use chrono_tz::Tz;

/// The window presets offered by the interactive menu.
pub const PRESETS: &[&str] = &["1h", "6h", "12h", "24h", "48h", "72h", "7d", "14d", "30d"];

/// Parses a duration such as `90m`, `24h`, `7d` or `2w`. A bare number is taken as hours.
pub fn parse_duration(s: &str) -> crate::Result<Duration> {
    let s = s.trim().to_lowercase();
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (number, unit) = s.split_at(split);
    let number: i64 = number
        .parse()
        .map_err(|_| anyhow!("invalid duration '{}', expected a value like 24h or 7d", s))?;
    let duration = match unit.trim() {
        "s" | "sec" | "secs" | "second" | "seconds" => Duration::seconds(number),
        "m" | "min" | "mins" | "minute" | "minutes" => Duration::minutes(number),
        "" | "h" | "hr" | "hrs" | "hour" | "hours" => Duration::hours(number),
        "d" | "day" | "days" => Duration::days(number),
        "w" | "wk" | "week" | "weeks" => Duration::weeks(number),
        unit => anyhow::bail!(
            "invalid duration unit '{}', expected one of m, h, d or w (e.g. 24h or 7d)",
            unit
        ),
    };
    if duration <= Duration::zero() {
        anyhow::bail!("duration must be greater than zero");
    }
    Ok(duration)
}

/// Converts a naive timestamp, as entered by the user, to UTC using the same rules as the rest of
/// Chainsaw: the provided timezone, else the local timezone when requested, else UTC.
pub fn localise(
    timestamp: &NaiveDateTime,
    timezone: Option<Tz>,
    local: bool,
) -> crate::Result<DateTime<Utc>> {
    let utc = if let Some(timezone) = timezone {
        timezone
            .from_local_datetime(timestamp)
            .single()
            .map(|t| t.with_timezone(&Utc))
    } else if local {
        Local
            .from_local_datetime(timestamp)
            .single()
            .map(|t| t.with_timezone(&Utc))
    } else {
        Some(Utc.from_utc_datetime(timestamp))
    };
    utc.ok_or_else(|| anyhow!("failed to localise timestamp"))
}

/// The inverse of `localise`, used to hand a window to builders that take naive timestamps.
pub fn delocalise(timestamp: &DateTime<Utc>, timezone: Option<Tz>, local: bool) -> NaiveDateTime {
    if let Some(timezone) = timezone {
        timestamp.with_timezone(&timezone).naive_local()
    } else if local {
        timestamp.with_timezone(&Local).naive_local()
    } else {
        timestamp.naive_utc()
    }
}

/// An inclusive time range; either end may be open.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Window {
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
}

impl Window {
    /// Builds a window from the common `--from`, `--to`, `--last` and `--anchor` options.
    /// `--last` ends at the anchor, or now when no anchor is given.
    pub fn resolve(
        from: Option<NaiveDateTime>,
        to: Option<NaiveDateTime>,
        last: Option<&str>,
        anchor: Option<NaiveDateTime>,
        timezone: Option<Tz>,
        local: bool,
    ) -> crate::Result<Self> {
        if let Some(last) = last {
            let duration = parse_duration(last)?;
            let end = match anchor {
                Some(anchor) => localise(&anchor, timezone, local)?,
                None => Utc::now(),
            };
            return Ok(Self {
                from: Some(end - duration),
                to: Some(end),
            });
        }
        Ok(Self {
            from: from.map(|f| localise(&f, timezone, local)).transpose()?,
            to: to.map(|t| localise(&t, timezone, local)).transpose()?,
        })
    }

    pub fn contains(&self, timestamp: &DateTime<Utc>) -> bool {
        self.from.map(|f| *timestamp >= f).unwrap_or(true)
            && self.to.map(|t| *timestamp <= t).unwrap_or(true)
    }

    pub fn is_open(&self) -> bool {
        self.from.is_none() && self.to.is_none()
    }

    pub fn describe(&self) -> String {
        let fmt = |t: &Option<DateTime<Utc>>| {
            t.map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                .unwrap_or_else(|| "*".to_string())
        };
        format!("{} to {}", fmt(&self.from), fmt(&self.to))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_durations() {
        assert_eq!(parse_duration("24h").unwrap(), Duration::hours(24));
        assert_eq!(parse_duration("48").unwrap(), Duration::hours(48));
        assert_eq!(parse_duration("7d").unwrap(), Duration::days(7));
        assert_eq!(parse_duration("2W").unwrap(), Duration::weeks(2));
        assert_eq!(parse_duration("90m").unwrap(), Duration::minutes(90));
        assert_eq!(parse_duration("3 days").unwrap(), Duration::days(3));
        assert!(parse_duration("0h").is_err());
        assert!(parse_duration("h").is_err());
        assert!(parse_duration("5y").is_err());
    }

    #[test]
    fn resolves_last_from_anchor() {
        let anchor =
            NaiveDateTime::parse_from_str("2024-01-10T12:00:00", "%Y-%m-%dT%H:%M:%S").unwrap();
        let w = Window::resolve(None, None, Some("48h"), Some(anchor), None, false).unwrap();
        assert_eq!(w.to.unwrap().naive_utc(), anchor);
        assert_eq!(w.from.unwrap().naive_utc(), anchor - Duration::hours(48));
        assert!(w.contains(&Utc.from_utc_datetime(&(anchor - Duration::hours(1)))));
        assert!(!w.contains(&Utc.from_utc_datetime(&(anchor + Duration::hours(1)))));
    }

    #[test]
    fn resolves_timezones() {
        let anchor =
            NaiveDateTime::parse_from_str("2024-01-10T12:00:00", "%Y-%m-%dT%H:%M:%S").unwrap();
        let tz: Tz = "Europe/Rome".parse().unwrap();
        let w = Window::resolve(None, None, Some("1h"), Some(anchor), Some(tz), false).unwrap();
        assert_eq!(w.to.unwrap().naive_utc(), anchor - Duration::hours(1));
        assert_eq!(delocalise(&w.to.unwrap(), Some(tz), false), anchor);
    }
}
