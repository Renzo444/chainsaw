//! A simplified view of Windows event log records, shared by the IOC, process and persistence
//! analyses.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use chrono::{DateTime, NaiveDateTime, Utc};
use rayon::prelude::*;
use serde::Serialize;
use serde_json::Value as Json;

use crate::file::evtx::Parser;
use crate::file::get_files;
use crate::findings::{as_text, flatten};
use crate::window::Window;

#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub timestamp: DateTime<Utc>,
    pub host: String,
    pub channel: String,
    pub provider: String,
    pub event_id: u32,
    pub record_id: u64,
    /// The event data, flattened to field name and text.
    pub fields: BTreeMap<String, String>,
    pub file: PathBuf,
}

impl Event {
    pub fn from_record(
        timestamp: DateTime<Utc>,
        record_id: u64,
        data: &Json,
        file: &Path,
    ) -> Option<Self> {
        let system = data.get("Event")?.get("System")?;
        let text = |k: &str| system.get(k).map(as_text).unwrap_or_default();
        let provider = system
            .get("Provider_attributes")
            .and_then(|p| p.get("Name"))
            .map(as_text)
            .unwrap_or_default();
        let mut fields = BTreeMap::new();
        if let Some(event) = data.get("Event") {
            for key in ["EventData", "UserData"] {
                if let Some(d) = event.get(key) {
                    flatten(d, &mut fields);
                }
            }
        }
        // Some exported logs carry a zeroed record time; Sysmon also records the time itself.
        let timestamp = if timestamp.timestamp() <= 0 {
            fields
                .get("UtcTime")
                .and_then(|t| NaiveDateTime::parse_from_str(t, "%Y-%m-%d %H:%M:%S%.f").ok())
                .map(|t| t.and_utc())
                .unwrap_or(timestamp)
        } else {
            timestamp
        };
        Some(Self {
            timestamp,
            host: text("Computer"),
            channel: text("Channel"),
            provider,
            event_id: text("EventID").parse().unwrap_or_default(),
            record_id,
            fields,
            file: file.to_path_buf(),
        })
    }

    pub fn get(&self, field: &str) -> &str {
        self.fields.get(field).map(|s| s.as_str()).unwrap_or("")
    }

    pub fn is_sysmon(&self) -> bool {
        self.channel.eq_ignore_ascii_case("Microsoft-Windows-Sysmon/Operational")
    }

    pub fn is_channel(&self, channel: &str) -> bool {
        self.channel.eq_ignore_ascii_case(channel)
    }

    /// A short label such as `Sysmon 1` or `Security 4688`.
    pub fn label(&self) -> String {
        let channel = if self.is_sysmon() {
            "Sysmon"
        } else {
            let channel = self.channel.split('/').next().unwrap_or(&self.channel);
            channel.strip_prefix("Microsoft-Windows-").unwrap_or(channel)
        };
        format!("{} {}", channel, self.event_id)
    }
}

/// Lists the event log files under the provided paths.
pub fn evtx_files(paths: &[PathBuf], skip_errors: bool) -> crate::Result<Vec<PathBuf>> {
    let extensions = Some(HashSet::from(["evtx".to_string(), "evt".to_string()]));
    let mut files = vec![];
    for path in paths {
        files.extend(get_files(path, &extensions, skip_errors)?);
    }
    Ok(files)
}

/// Loads the events within the window that `keep` selects, from all of the event log files.
pub fn load<F>(
    files: &[PathBuf],
    window: &Window,
    skip_errors: bool,
    keep: F,
) -> crate::Result<Vec<Event>>
where
    F: Fn(&Event) -> bool + Sync,
{
    let results: Vec<crate::Result<Vec<Event>>> = files
        .par_iter()
        .map(|file| {
            let mut parser = match Parser::load(file) {
                Ok(p) => p,
                Err(e) if skip_errors => {
                    cs_eyellowln!("[!] failed to load file '{}' - {}", file.display(), e);
                    return Ok(vec![]);
                }
                Err(e) => {
                    return Err(anyhow!("failed to load '{}' - {}", file.display(), e));
                }
            };
            let mut events = vec![];
            for record in parser.parse() {
                let record = match record {
                    Ok(r) => r,
                    Err(e) if skip_errors => {
                        cs_debug!("[!] failed to parse record in '{}' - {}", file.display(), e);
                        continue;
                    }
                    Err(e) => {
                        return Err(anyhow!(
                            "failed to parse record in '{}' - {} (use --skip-errors to continue)",
                            file.display(),
                            e
                        ));
                    }
                };
                let Some(timestamp) = DateTime::from_timestamp(
                    record.timestamp.as_second(),
                    record.timestamp.subsec_nanosecond().max(0) as u32,
                ) else {
                    continue;
                };
                if !window.contains(&timestamp) {
                    continue;
                }
                if let Some(event) =
                    Event::from_record(timestamp, record.event_record_id, &record.data, file)
                    && keep(&event)
                {
                    events.push(event);
                }
            }
            Ok(events)
        })
        .collect();
    let mut events = vec![];
    for r in results {
        events.extend(r?);
    }
    events.sort_by(|a, b| {
        a.timestamp
            .cmp(&b.timestamp)
            .then(a.record_id.cmp(&b.record_id))
    });
    Ok(events)
}

/// Directories and file names that are user writable and commonly abused to stage malware.
pub fn is_suspicious_path(path: &str) -> bool {
    let p = path.to_lowercase().replace('/', "\\");
    const MARKERS: &[&str] = &[
        "\\appdata\\",
        "\\temp\\",
        "\\tmp\\",
        "\\users\\public\\",
        "\\programdata\\",
        "\\downloads\\",
        "\\desktop\\",
        "\\perflogs\\",
        "\\windows\\tasks\\",
        "\\recycle",
        "%temp%",
        "%appdata%",
        "%public%",
    ];
    const LOLBINS: &[&str] = &[
        "powershell",
        "pwsh",
        "cmd.exe /c",
        "cmd /c",
        "%comspec%",
        "mshta",
        "rundll32",
        "regsvr32",
        "wscript",
        "cscript",
        "certutil",
        "bitsadmin",
        "-enc",
        "frombase64string",
        "http://",
        "https://",
        "\\\\",
    ];
    // Well known software that legitimately runs from user writable locations.
    const ALLOWED: &[&str] = &[
        "\\programdata\\microsoft\\windows defender\\",
        "\\appdata\\local\\microsoft\\onedrive\\",
        "\\appdata\\local\\microsoft\\teams\\",
    ];
    if ALLOWED.iter().any(|a| p.contains(a)) && !LOLBINS.iter().any(|m| p.contains(m)) {
        return false;
    }
    MARKERS.iter().any(|m| p.contains(m))
        || LOLBINS.iter().any(|m| p.contains(m))
        || p.starts_with("\\\\")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn builds_events() {
        let data = json!({"Event": {
            "System": {"Computer": "PC", "Channel": "Microsoft-Windows-Sysmon/Operational",
                       "EventID": 1, "Provider_attributes": {"Name": "Microsoft-Windows-Sysmon"}},
            "EventData": {"Image": "C:\\a.exe", "ProcessId": 4}
        }});
        let e = Event::from_record(Utc::now(), 7, &data, Path::new("x.evtx")).unwrap();
        assert_eq!(e.host, "PC");
        assert_eq!(e.event_id, 1);
        assert_eq!(e.get("ProcessId"), "4");
        assert_eq!(e.label(), "Sysmon 1");
        assert!(e.is_sysmon());

        let data = json!({"Event": {
            "System": {"Computer": "PC", "Channel": "Security", "EventID": {"#text": 4698}},
            "UserData": {"Task": {"TaskName": "\\x"}}
        }});
        let e = Event::from_record(Utc::now(), 8, &data, Path::new("x.evtx")).unwrap();
        assert_eq!(e.event_id, 4698);
        assert_eq!(e.get("TaskName"), "\\x");
        assert_eq!(e.label(), "Security 4698");
    }

    #[test]
    fn flags_suspicious_paths() {
        assert!(is_suspicious_path(r"C:\Users\bob\AppData\Roaming\x.exe"));
        assert!(is_suspicious_path(r"%COMSPEC% /c echo"));
        assert!(is_suspicious_path(r"powershell.exe -enc AAAA"));
        assert!(!is_suspicious_path(r"C:\Windows\System32\svchost.exe -k netsvcs"));
        assert!(!is_suspicious_path(r#""C:\Program Files\Vendor\agent.exe""#));
        assert!(!is_suspicious_path(
            r#""C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe""#
        ));
    }
}
