//! Automated sweep of the most common Windows persistence locations, across event logs, registry
//! hives and collected files, with each item ranked by severity.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use notatin::cell_key_node::CellKeyNode;
use notatin::cell_value::CellValue;
use prettytable::{Table, row};
use regex::Regex;
use serde::Serialize;
use serde_json::json;

use crate::events::{self, Event, is_suspicious_path};
use crate::file::hve::Parser as HveParser;
use crate::findings::{self, Evidence, Finding, Report, truncate};
use crate::ioc::{Output, display_paths, window_text};
use crate::rule::Level;
use crate::window::Window;

#[derive(Clone, Debug, Serialize)]
pub struct Item {
    pub timestamp: Option<DateTime<Utc>>,
    pub host: String,
    pub mechanism: String,
    pub technique: String,
    pub location: String,
    pub name: String,
    pub data: String,
    pub level: Level,
    pub source: String,
}

fn raise(level: Level) -> Level {
    match level {
        Level::Info => Level::Low,
        Level::Low => Level::Medium,
        Level::Medium => Level::High,
        _ => Level::Critical,
    }
}

/// Registry locations that are used for persistence, matched against the lower cased key path.
/// Returns (mechanism, technique).
pub fn registry_mechanism(path: &str) -> Option<(&'static str, &'static str)> {
    let p = path.to_lowercase().replace('/', "\\");
    let m = if p.contains("\\currentversion\\run") || p.contains("\\policies\\explorer\\run") {
        ("Run key", "T1547.001")
    } else if p.contains("\\winlogon\\userinit")
        || p.contains("\\winlogon\\shell")
        || p.contains("\\winlogon\\notify")
    {
        ("Winlogon", "T1547.004")
    } else if p.contains("\\image file execution options\\") && p.ends_with("\\debugger")
        || p.contains("\\silentprocessexit\\")
    {
        ("Image File Execution Options", "T1546.012")
    } else if p.contains("\\appinit_dlls") {
        ("AppInit DLLs", "T1546.010")
    } else if p.contains("\\active setup\\installed components\\") && p.ends_with("\\stubpath") {
        ("Active Setup", "T1547.014")
    } else if p.contains("\\control\\lsa\\")
        && (p.ends_with("packages") || p.contains("\\notification packages"))
    {
        ("LSA package", "T1547.002")
    } else if p.contains("\\control\\print\\monitors\\") {
        ("Print monitor", "T1547.010")
    } else if p.contains("\\command processor\\autorun") {
        ("Command Processor AutoRun", "T1546")
    } else if p.contains("\\services\\")
        && (p.ends_with("\\imagepath") || p.ends_with("\\servicedll"))
    {
        ("Service", "T1543.003")
    } else if p.contains("\\environment\\userinitmprlogonscript") {
        ("Logon script", "T1037.001")
    } else if p.contains("\\user shell folders\\startup") || p.contains("\\shell folders\\startup")
    {
        ("Startup folder redirect", "T1547.001")
    } else if p.contains("\\session manager\\bootexecute") {
        ("BootExecute", "T1547.001")
    } else if p.contains("\\microsoft\\netsh\\") {
        ("Netsh helper", "T1546.007")
    } else if p.contains("\\clsid\\") && p.contains("\\inprocserver32") {
        ("COM hijack", "T1546.015")
    } else if p.contains("\\windows nt\\currentversion\\windows\\load")
        || p.contains("\\windows nt\\currentversion\\windows\\run")
    {
        ("Windows Load/Run", "T1547.001")
    } else {
        return None;
    };
    Some(m)
}

pub struct CommandPattern {
    regex: Regex,
    mechanism: &'static str,
    technique: &'static str,
}

pub fn command_patterns() -> Vec<CommandPattern> {
    let p = |re: &str, mechanism, technique| CommandPattern {
        regex: Regex::new(&format!("(?i){}", re)).expect("valid persistence regex"),
        mechanism,
        technique,
    };
    vec![
        p(
            r"schtasks(\.exe)?\W.*/create",
            "Scheduled task (command)",
            "T1053.005",
        ),
        p(
            r"(register|new)-scheduledtask",
            "Scheduled task (command)",
            "T1053.005",
        ),
        p(
            r"\bsc(\.exe)?\s+(\\\\\S+\s+)?(create|config)\b",
            "Service (command)",
            "T1543.003",
        ),
        p(r"new-service\b", "Service (command)", "T1543.003"),
        p(
            r"reg(\.exe)?\s+add\s.*\\(run|runonce|winlogon|image file execution options|command processor|environment)",
            "Registry autorun (command)",
            "T1547.001",
        ),
        p(
            r"(set|new)-itemproperty.*\\(run|runonce|winlogon)\b",
            "Registry autorun (command)",
            "T1547.001",
        ),
        p(
            r"(root\\subscription|__eventfilter|commandlineeventconsumer|activescripteventconsumer)",
            "WMI subscription (command)",
            "T1546.003",
        ),
        p(
            r"\bnet1?(\.exe)?\s+user\s+\S+.*\s/add",
            "Account created (command)",
            "T1136.001",
        ),
        p(
            r"\bnet1?(\.exe)?\s+(local)?group\s+.*admin.*\s/add",
            "Admin group membership (command)",
            "T1098",
        ),
    ]
}

fn task_command(xml: &str) -> String {
    let re = Regex::new(r"(?is)<Command>(.*?)</Command>(?:\s*<Arguments>(.*?)</Arguments>)?")
        .expect("valid task regex");
    re.captures_iter(xml)
        .map(|c| {
            let cmd = c.get(1).map(|m| m.as_str().trim()).unwrap_or("");
            let args = c.get(2).map(|m| m.as_str().trim()).unwrap_or("");
            if args.is_empty() {
                cmd.to_string()
            } else {
                format!("{} {}", cmd, args)
            }
        })
        .map(|c| {
            c.replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&quot;", "\"")
                .replace("&apos;", "'")
                .replace("&amp;", "&")
        })
        .collect::<Vec<_>>()
        .join(" ; ")
}

fn item(e: &Event, mechanism: &str, technique: &str, name: &str, data: &str, level: Level) -> Item {
    Item {
        timestamp: Some(e.timestamp),
        host: e.host.clone(),
        mechanism: mechanism.to_string(),
        technique: technique.to_string(),
        location: e.label(),
        name: name.to_string(),
        data: data.to_string(),
        level,
        source: "event log".to_string(),
    }
}

fn suspicious_level(data: &str, base: Level) -> Level {
    if is_suspicious_path(data) {
        raise(base)
    } else {
        base
    }
}

/// Turns an event into a persistence item when it records persistence being set up.
pub fn from_event(e: &Event, patterns: &[CommandPattern]) -> Option<Item> {
    let g = |k: &str| e.get(k);
    let security = e.is_channel("Security");
    match (e.event_id, e.channel.as_str()) {
        (7045, _) if e.is_channel("System") => {
            let path = g("ImagePath");
            Some(item(
                e,
                "Service installed",
                "T1543.003",
                g("ServiceName"),
                path,
                suspicious_level(path, Level::Medium),
            ))
        }
        (4697, _) if security => {
            let path = g("ServiceFileName");
            Some(item(
                e,
                "Service installed",
                "T1543.003",
                g("ServiceName"),
                path,
                suspicious_level(path, Level::Medium),
            ))
        }
        (4698 | 4702, _) if security => {
            let command = task_command(g("TaskContent"));
            let (mechanism, base) = if e.event_id == 4698 {
                ("Scheduled task created", Level::Medium)
            } else {
                ("Scheduled task updated", Level::Low)
            };
            Some(item(
                e,
                mechanism,
                "T1053.005",
                g("TaskName"),
                &command,
                suspicious_level(&command, base),
            ))
        }
        (106, _) if e.channel.to_lowercase().contains("taskscheduler") => Some(item(
            e,
            "Scheduled task registered",
            "T1053.005",
            g("TaskName"),
            &format!("registered by {}", g("UserContext")),
            Level::Low,
        )),
        (4720, _) if security => Some(item(
            e,
            "Account created",
            "T1136.001",
            g("TargetUserName"),
            &format!("by {}", g("SubjectUserName")),
            Level::Medium,
        )),
        (4728 | 4732 | 4756, _) if security => {
            let group = g("TargetUserName");
            let lower_group = group.to_lowercase();
            let level = if lower_group.contains("admin") {
                Level::High
            } else if lower_group.contains("remote desktop")
                || lower_group.contains("remote management")
            {
                Level::Medium
            } else {
                Level::Low
            };
            let member = [g("MemberName"), g("MemberSid")]
                .into_iter()
                .find(|m| !m.is_empty() && *m != "-")
                .unwrap_or("");
            Some(item(
                e,
                "Added to group",
                "T1098",
                group,
                &format!("{} by {}", member, g("SubjectUserName")),
                level,
            ))
        }
        (5861, _) if e.channel.to_lowercase().contains("wmi-activity") => Some(item(
            e,
            "WMI subscription",
            "T1546.003",
            g("CONSUMER"),
            &format!("{} {}", g("Namespace"), g("PossibleCause")),
            Level::High,
        )),
        (19..=21, _) if e.is_sysmon() => {
            let data = [g("Destination"), g("Query"), g("Consumer")]
                .into_iter()
                .filter(|v| !v.is_empty())
                .collect::<Vec<_>>()
                .join(" ");
            Some(item(
                e,
                "WMI subscription",
                "T1546.003",
                g("Name"),
                &data,
                Level::High,
            ))
        }
        (12..=14, _) if e.is_sysmon() => {
            let target = g("TargetObject");
            let (mechanism, technique) = registry_mechanism(target)?;
            if g("EventType") == "DeleteValue" || g("EventType") == "DeleteKey" {
                return None;
            }
            let details = g("Details");
            Some(Item {
                data: format!("{} (by {})", details, g("Image")),
                ..item(
                    e,
                    mechanism,
                    technique,
                    target,
                    "",
                    suspicious_level(details, Level::Medium),
                )
            })
        }
        (4657, _) if security => {
            let target = format!("{}\\{}", g("ObjectName"), g("ObjectValueName"));
            let (mechanism, technique) = registry_mechanism(&target)?;
            let value = g("NewValue");
            Some(item(
                e,
                mechanism,
                technique,
                &target,
                value,
                suspicious_level(value, Level::Medium),
            ))
        }
        (11, _) if e.is_sysmon() => {
            let file = g("TargetFilename");
            let lower_file = file.to_lowercase();
            if lower_file.contains("\\start menu\\programs\\startup\\") {
                Some(item(
                    e,
                    "Startup folder file",
                    "T1547.001",
                    file,
                    &format!("created by {}", g("Image")),
                    Level::High,
                ))
            } else if lower_file.contains("\\windows\\system32\\tasks\\") {
                Some(item(
                    e,
                    "Scheduled task file",
                    "T1053.005",
                    file,
                    &format!("created by {}", g("Image")),
                    Level::Medium,
                ))
            } else {
                None
            }
        }
        (1, _) | (4688, _) if e.is_sysmon() || security => {
            let command = g("CommandLine");
            let pattern = patterns.iter().find(|p| p.regex.is_match(command))?;
            let image = if e.is_sysmon() {
                g("Image")
            } else {
                g("NewProcessName")
            };
            Some(item(
                e,
                pattern.mechanism,
                pattern.technique,
                image,
                command,
                suspicious_level(command, Level::Medium),
            ))
        }
        _ => None,
    }
}

fn value_text(value: &CellValue) -> String {
    match value {
        CellValue::MultiString(v) => v.join(", "),
        CellValue::None | CellValue::Error => String::new(),
        other => other.to_string(),
    }
}

struct Hive {
    path: PathBuf,
    kind: HiveKind,
}

#[derive(Clone, Copy, PartialEq)]
enum HiveKind {
    Software,
    System,
    NtUser,
    UsrClass,
}

/// Walks the paths for registry hives, startup folder files and scheduled task files.
fn collect(paths: &[PathBuf]) -> (Vec<Hive>, Vec<PathBuf>, Vec<PathBuf>) {
    let mut hives = vec![];
    let mut startup = vec![];
    let mut tasks = vec![];
    let mut stack: Vec<PathBuf> = paths.to_vec();
    while let Some(path) = stack.pop() {
        if path.is_dir() {
            if let Ok(entries) = fs::read_dir(&path) {
                stack.extend(entries.flatten().map(|e| e.path()));
            }
            continue;
        }
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_uppercase())
            .unwrap_or_default();
        let kind = match name.as_str() {
            "SOFTWARE" => Some(HiveKind::Software),
            "SYSTEM" => Some(HiveKind::System),
            "NTUSER.DAT" => Some(HiveKind::NtUser),
            "USRCLASS.DAT" => Some(HiveKind::UsrClass),
            _ => None,
        };
        if let Some(kind) = kind {
            hives.push(Hive { path, kind });
            continue;
        }
        let lower = path.to_string_lossy().to_lowercase().replace('/', "\\");
        if lower.contains("\\start menu\\programs\\startup\\")
            && !name.eq_ignore_ascii_case("desktop.ini")
        {
            startup.push(path);
        } else if lower.contains("\\windows\\system32\\tasks\\") && path.extension().is_none() {
            tasks.push(path);
        }
    }
    (hives, startup, tasks)
}

struct HiveReader<'a> {
    parser: HveParser,
    hive: &'a Hive,
    host: String,
    items: Vec<Item>,
}

impl HiveReader<'_> {
    fn key(&mut self, path: &str) -> Option<CellKeyNode> {
        self.parser.inner.get_key(path, false).ok().flatten()
    }

    fn label(&self) -> String {
        format!("registry: {}", self.hive.path.display())
    }

    fn push(
        &mut self,
        key: &CellKeyNode,
        value: &str,
        data: &str,
        mechanism: &str,
        technique: &str,
        level: Level,
    ) {
        self.items.push(Item {
            timestamp: Some(key.last_key_written_date_and_time()),
            host: self.host.clone(),
            mechanism: mechanism.to_string(),
            technique: technique.to_string(),
            location: format!("{}\\{}", key.get_pretty_path(), value),
            name: value.to_string(),
            data: data.to_string(),
            level,
            source: self.label(),
        });
    }

    /// Reports every value in the key; suspicious ones are raised.
    fn values(&mut self, path: &str, mechanism: &str, technique: &str, base: Level) {
        if let Some(key) = self.key(path) {
            let values: Vec<(String, String)> = key
                .value_iter()
                .map(|v| (v.get_pretty_name(), value_text(&v.get_content().0)))
                .collect();
            for (name, data) in values {
                self.push(
                    &key,
                    &name,
                    &data,
                    mechanism,
                    technique,
                    suspicious_level(&data, base.clone()),
                );
            }
        }
    }

    /// Reports the value if it differs from what Windows ships with.
    fn unexpected(
        &mut self,
        path: &str,
        value: &str,
        expected: &[&str],
        mechanism: &str,
        technique: &str,
        level: Level,
    ) {
        if let Some(key) = self.key(path)
            && let Some(v) = key.get_value(value)
        {
            let data = value_text(&v.get_content().0);
            let normalised = data.to_lowercase().replace(' ', "");
            let parts: Vec<&str> = normalised
                .split([',', ';'])
                .map(|p| p.trim())
                .filter(|p| !p.is_empty())
                .collect();
            if parts
                .iter()
                .any(|p| !expected.iter().any(|e| p.ends_with(e)))
            {
                self.push(&key, value, &data, mechanism, technique, level);
            }
        }
    }

    /// Reports a value of each sub key when it looks suspicious.
    #[allow(clippy::too_many_arguments)]
    fn sub_values(
        &mut self,
        path: &str,
        sub_path: &str,
        value: &str,
        mechanism: &str,
        technique: &str,
        level: Level,
        only_suspicious: bool,
    ) {
        let Some(mut key) = self.key(path) else {
            return;
        };
        for mut sub in key.read_sub_keys(&mut self.parser.inner) {
            let target = if sub_path.is_empty() {
                Some(sub.clone())
            } else {
                sub.get_sub_key_by_path(&mut self.parser.inner, sub_path)
            };
            let Some(target) = target else {
                continue;
            };
            if let Some(v) = target.get_value(value) {
                let data = value_text(&v.get_content().0);
                if data.is_empty() || (only_suspicious && !is_suspicious_path(&data)) {
                    continue;
                }
                let level = if only_suspicious {
                    level.clone()
                } else {
                    suspicious_level(&data, level.clone())
                };
                let name = format!("{} ({})", sub.key_name, value);
                self.push(&target, &name, &data, mechanism, technique, level);
            }
        }
    }
}

fn computer_name(parser: &mut HveParser) -> Option<String> {
    let select = parser.inner.get_key("Select", false).ok()??;
    let current = match select.get_value("Current")?.get_content().0 {
        CellValue::U32(n) => n,
        _ => return None,
    };
    let key = parser
        .inner
        .get_key(
            &format!(
                "ControlSet{:03}\\Control\\ComputerName\\ComputerName",
                current
            ),
            false,
        )
        .ok()??;
    Some(value_text(&key.get_value("ComputerName")?.get_content().0))
}

fn sweep_hive(hive: &Hive, host: &str) -> crate::Result<Vec<Item>> {
    let parser = HveParser::load(&hive.path)?;
    let mut r = HiveReader {
        parser,
        hive,
        host: host.to_string(),
        items: vec![],
    };
    let run_keys = [
        r"Microsoft\Windows\CurrentVersion\Run",
        r"Microsoft\Windows\CurrentVersion\RunOnce",
        r"Microsoft\Windows\CurrentVersion\RunOnceEx",
        r"Microsoft\Windows\CurrentVersion\RunServices",
        r"Microsoft\Windows\CurrentVersion\RunServicesOnce",
        r"Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        r"Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        r"Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    ];
    match hive.kind {
        HiveKind::Software => {
            for key in run_keys {
                r.values(key, "Run key", "T1547.001", Level::Low);
            }
            let winlogon = r"Microsoft\Windows NT\CurrentVersion\Winlogon";
            r.unexpected(
                winlogon,
                "Userinit",
                &["userinit.exe"],
                "Winlogon",
                "T1547.004",
                Level::Critical,
            );
            r.unexpected(
                winlogon,
                "Shell",
                &["explorer.exe"],
                "Winlogon",
                "T1547.004",
                Level::Critical,
            );
            r.sub_values(
                r"Microsoft\Windows NT\CurrentVersion\Winlogon\Notify",
                "",
                "DLLName",
                "Winlogon",
                "T1547.004",
                Level::High,
                false,
            );
            r.sub_values(
                r"Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
                "",
                "Debugger",
                "Image File Execution Options",
                "T1546.012",
                Level::High,
                false,
            );
            r.sub_values(
                r"Microsoft\Windows NT\CurrentVersion\SilentProcessExit",
                "",
                "MonitorProcess",
                "Image File Execution Options",
                "T1546.012",
                Level::High,
                false,
            );
            r.unexpected(
                r"Microsoft\Windows NT\CurrentVersion\Windows",
                "AppInit_DLLs",
                &[],
                "AppInit DLLs",
                "T1546.010",
                Level::High,
            );
            r.unexpected(
                r"Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows",
                "AppInit_DLLs",
                &[],
                "AppInit DLLs",
                "T1546.010",
                Level::High,
            );
            r.sub_values(
                r"Microsoft\Active Setup\Installed Components",
                "",
                "StubPath",
                "Active Setup",
                "T1547.014",
                Level::High,
                true,
            );
            r.unexpected(
                r"Microsoft\Command Processor",
                "AutoRun",
                &[],
                "Command Processor AutoRun",
                "T1546",
                Level::High,
            );
            r.values(r"Microsoft\Netsh", "Netsh helper", "T1546.007", Level::Info);
        }
        HiveKind::System => {
            let current = r
                .key("Select")
                .and_then(|k| k.get_value("Current"))
                .and_then(|v| match v.get_content().0 {
                    CellValue::U32(n) => Some(n),
                    _ => None,
                })
                .unwrap_or(1);
            let cs = format!("ControlSet{:03}", current);
            r.sub_values(
                &format!(r"{}\Services", cs),
                "",
                "ImagePath",
                "Service",
                "T1543.003",
                Level::High,
                true,
            );
            r.sub_values(
                &format!(r"{}\Services", cs),
                "Parameters",
                "ServiceDll",
                "Service",
                "T1543.003",
                Level::High,
                true,
            );
            let lsa = format!(r"{}\Control\Lsa", cs);
            r.unexpected(
                &lsa,
                "Authentication Packages",
                &["msv1_0", "\"\""],
                "LSA package",
                "T1547.002",
                Level::High,
            );
            r.unexpected(
                &lsa,
                "Security Packages",
                &[
                    "kerberos", "msv1_0", "schannel", "wdigest", "tspkg", "pku2u", "cloudap",
                    "\"\"", "livessp", "negoexts", "msoidssp",
                ],
                "LSA package",
                "T1547.005",
                Level::High,
            );
            r.unexpected(
                &lsa,
                "Notification Packages",
                &["scecli", "rassfm"],
                "LSA package",
                "T1556.002",
                Level::High,
            );
            r.unexpected(
                &format!(r"{}\Control\Session Manager", cs),
                "BootExecute",
                &["autocheckautochk*", "autocheckautochk/q/v*"],
                "BootExecute",
                "T1547.001",
                Level::High,
            );
            r.sub_values(
                &format!(r"{}\Control\Print\Monitors", cs),
                "",
                "Driver",
                "Print monitor",
                "T1547.010",
                Level::Medium,
                false,
            );
            // Drop the stock print monitors.
            let stock = [
                "localspl.dll",
                "tcpmon.dll",
                "usbmon.dll",
                "wsdmon.dll",
                "apmon.dll",
                "appmon.dll",
                "fxsmon.dll",
                "mfpmon.dll",
                "pjlmon.dll",
            ];
            r.items.retain(|i| {
                i.mechanism != "Print monitor" || !stock.contains(&i.data.to_lowercase().as_str())
            });
        }
        HiveKind::NtUser => {
            for key in run_keys.iter().filter(|k| !k.starts_with("Wow6432Node")) {
                r.values(
                    &format!(r"Software\{}", key),
                    "Run key (user)",
                    "T1547.001",
                    Level::Low,
                );
            }
            let windows = r"Software\Microsoft\Windows NT\CurrentVersion\Windows";
            r.unexpected(
                windows,
                "Load",
                &[],
                "Windows Load/Run",
                "T1547.001",
                Level::High,
            );
            r.unexpected(
                windows,
                "Run",
                &[],
                "Windows Load/Run",
                "T1547.001",
                Level::High,
            );
            r.unexpected(
                r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
                "Shell",
                &["explorer.exe"],
                "Winlogon",
                "T1547.004",
                Level::Critical,
            );
            r.unexpected(
                "Environment",
                "UserInitMprLogonScript",
                &[],
                "Logon script",
                "T1037.001",
                Level::High,
            );
            r.unexpected(
                r"Software\Microsoft\Command Processor",
                "AutoRun",
                &[],
                "Command Processor AutoRun",
                "T1546",
                Level::High,
            );
            r.unexpected(
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
                "Startup",
                &["%userprofile%\\appdata\\roaming\\microsoft\\windows\\startmenu\\programs\\startup"],
                "Startup folder redirect",
                "T1547.001",
                Level::High,
            );
            r.sub_values(
                r"Software\Classes\CLSID",
                "InprocServer32",
                "(default)",
                "COM hijack",
                "T1546.015",
                Level::High,
                true,
            );
        }
        HiveKind::UsrClass => {
            r.sub_values(
                "CLSID",
                "InprocServer32",
                "(default)",
                "COM hijack",
                "T1546.015",
                Level::High,
                true,
            );
        }
    }
    Ok(r.items)
}

fn read_text(path: &Path) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    if bytes.starts_with(&[0xFF, 0xFE]) {
        let units: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        Some(String::from_utf16_lossy(&units))
    } else {
        Some(String::from_utf8_lossy(&bytes).to_string())
    }
}

fn modified(path: &Path) -> Option<DateTime<Utc>> {
    fs::metadata(path)
        .ok()?
        .modified()
        .ok()
        .map(DateTime::<Utc>::from)
}

fn sweep_files(startup: &[PathBuf], tasks: &[PathBuf], host: &str) -> Vec<Item> {
    let mut items = vec![];
    for path in startup {
        let p = path.to_string_lossy().to_string();
        let ext = path
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        let executable = [
            "exe", "dll", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "hta", "scr", "wsf",
            "jar",
        ]
        .contains(&ext.as_str());
        items.push(Item {
            timestamp: modified(path),
            host: host.to_string(),
            mechanism: "Startup folder file".to_string(),
            technique: "T1547.001".to_string(),
            location: p.clone(),
            name: path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default(),
            data: p,
            level: if executable {
                Level::High
            } else {
                Level::Medium
            },
            source: "file".to_string(),
        });
    }
    for path in tasks {
        let Some(xml) = read_text(path) else {
            continue;
        };
        if !xml.contains("<Task") {
            continue;
        }
        let command = task_command(&xml);
        let p = path.to_string_lossy().to_string();
        let stock = p
            .to_lowercase()
            .replace('/', "\\")
            .contains("\\tasks\\microsoft\\");
        let suspicious = is_suspicious_path(&command);
        if stock && !suspicious {
            continue;
        }
        items.push(Item {
            timestamp: modified(path),
            host: host.to_string(),
            mechanism: "Scheduled task".to_string(),
            technique: "T1053.005".to_string(),
            location: p,
            name: path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default(),
            data: command,
            level: if suspicious { Level::High } else { Level::Low },
            source: "file".to_string(),
        });
    }
    items
}

/// Collapses repeats of the same persistence item into one finding each.
pub fn to_findings(items: &[Item]) -> Vec<Finding> {
    let mut grouped: BTreeMap<(String, String, String, String), Finding> = BTreeMap::new();
    for i in items {
        let finding = grouped
            .entry((
                i.host.clone(),
                i.mechanism.clone(),
                i.name.clone(),
                i.data.clone(),
            ))
            .or_insert_with(|| {
                let title = if i.name.is_empty() {
                    i.mechanism.clone()
                } else {
                    format!("{}: {}", i.mechanism, truncate(&i.name, 80))
                };
                let mut f = Finding::new(&title, i.level.clone(), &i.mechanism, &i.source);
                f.tactics = vec!["persistence".to_string()];
                f.techniques = vec![i.technique.clone()];
                f
            });
        if findings::level_weight(&i.level) > findings::level_weight(&finding.level) {
            finding.level = i.level.clone();
        }
        finding.add(Evidence {
            timestamp: i.timestamp,
            host: i.host.clone(),
            event: i.location.clone(),
            detail: truncate(&i.data, 240),
        });
    }
    let mut findings: Vec<Finding> = grouped.into_values().collect();
    findings::rank(&mut findings);
    findings
}

pub struct Options {
    pub paths: Vec<PathBuf>,
    pub window: Window,
    pub output: Output,
    pub skip_errors: bool,
    pub min_level: Option<Level>,
}

pub fn run(opts: Options) -> crate::Result<()> {
    let (hives, startup, tasks) = collect(&opts.paths);
    let files = events::evtx_files(&opts.paths, opts.skip_errors)?;
    cs_eprintln!(
        "[+] Sweeping for persistence in {} event logs, {} registry hives, {} startup files and {} task files ({})",
        files.len(),
        hives.len(),
        startup.len(),
        tasks.len(),
        window_text(&opts.window).to_lowercase()
    );
    if files.is_empty() && hives.is_empty() && startup.is_empty() && tasks.is_empty() {
        anyhow::bail!(
            "No event logs, registry hives or persistence files were found in the provided paths"
        );
    }

    let patterns = command_patterns();
    let mut items = vec![];
    if !files.is_empty() {
        let events = events::load(&files, &opts.window, opts.skip_errors, |e| {
            from_event(e, &patterns).is_some()
        })?;
        items.extend(events.iter().filter_map(|e| from_event(e, &patterns)));
    }

    // Name registry and file items after the host in the SYSTEM hive, where there is one.
    let mut host = String::new();
    for hive in hives.iter().filter(|h| h.kind == HiveKind::System) {
        if let Ok(mut parser) = HveParser::load(&hive.path)
            && let Some(name) = computer_name(&mut parser)
        {
            host = name;
            break;
        }
    }
    let mut static_items = vec![];
    for hive in &hives {
        match sweep_hive(hive, &host) {
            Ok(found) => static_items.extend(found),
            Err(e) if opts.skip_errors => {
                cs_eyellowln!("[!] failed to read hive '{}' - {}", hive.path.display(), e);
            }
            Err(e) => {
                return Err(anyhow!(
                    "failed to read hive '{}' - {} (use --skip-errors to continue)",
                    hive.path.display(),
                    e
                ));
            }
        }
    }
    static_items.extend(sweep_files(&startup, &tasks, &host));
    // Registry and file times are last-written times, so the window applies to them too.
    static_items.retain(|i| i.timestamp.is_none_or(|t| opts.window.contains(&t)));
    items.extend(static_items);
    if let Some(min) = &opts.min_level {
        let min = findings::level_weight(min);
        items.retain(|i| findings::level_weight(&i.level) >= min);
    }

    let findings = to_findings(&items);
    let found = findings.len();
    match opts.output {
        Output::Json => {
            cs_print_json!(&json!({"findings": findings, "items": items}))?;
        }
        Output::Markdown => {
            let report = Report {
                title: "Chainsaw persistence sweep".to_string(),
                meta: vec![
                    ("Evidence".to_string(), display_paths(&opts.paths)),
                    ("Time window".to_string(), window_text(&opts.window)),
                    (
                        "Sources".to_string(),
                        format!(
                            "{} event logs, {} registry hives, {} startup files, {} task files",
                            files.len(),
                            hives.len(),
                            startup.len(),
                            tasks.len()
                        ),
                    ),
                ],
                findings,
                sections: vec![],
            };
            cs_print!("{}", report.to_markdown());
        }
        Output::Std => {
            if findings.is_empty() {
                cs_eprintln!("[+] No persistence found");
            } else {
                let mut table = Table::new();
                table.set_format(crate::cli::table_format());
                table.set_titles(row![
                    "#",
                    "severity",
                    "mechanism",
                    "name",
                    "data",
                    "host",
                    "seen (UTC)",
                    "count",
                    "source"
                ]);
                for f in &findings {
                    let e = &f.evidence[0];
                    table.add_row(row![
                        f.rank,
                        f.level,
                        f.category,
                        truncate(f.title.split_once(": ").map(|(_, n)| n).unwrap_or(""), 50),
                        truncate(&e.detail, 70),
                        e.host,
                        findings::fmt_time(&f.first_seen),
                        f.count,
                        truncate(&e.event, 40)
                    ]);
                }
                cs_print_table!(table);
            }
        }
    }
    cs_eprintln!(
        "[+] Found {} persistence items ({} entries)",
        found,
        items.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(id: u32, channel: &str, fields: &[(&str, &str)]) -> Event {
        Event {
            timestamp: Utc::now(),
            host: "PC".into(),
            channel: channel.into(),
            provider: String::new(),
            event_id: id,
            record_id: 1,
            fields: fields
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            file: PathBuf::new(),
        }
    }

    #[test]
    fn maps_registry_locations() {
        assert_eq!(
            registry_mechanism(r"HKU\S-1\Software\Microsoft\Windows\CurrentVersion\Run\evil")
                .unwrap()
                .0,
            "Run key"
        );
        assert_eq!(
            registry_mechanism(r"HKLM\System\CurrentControlSet\Services\x\ImagePath")
                .unwrap()
                .0,
            "Service"
        );
        assert_eq!(
            registry_mechanism(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe\Debugger").unwrap().0,
            "Image File Execution Options"
        );
        assert!(registry_mechanism(r"HKLM\Software\Vendor\Settings").is_none());
    }

    #[test]
    fn detects_persistence_events() {
        let patterns = command_patterns();
        let svc = event(
            7045,
            "System",
            &[
                ("ServiceName", "evil"),
                ("ImagePath", r"C:\Users\Public\evil.exe"),
            ],
        );
        let i = from_event(&svc, &patterns).unwrap();
        assert_eq!(
            (i.mechanism.as_str(), i.level.clone()),
            ("Service installed", Level::High)
        );

        let task = event(
            4698,
            "Security",
            &[
                ("TaskName", r"\Updater"),
                (
                    "TaskContent",
                    "<Task><Actions><Exec><Command>powershell.exe</Command><Arguments>-enc AAA</Arguments></Exec></Actions></Task>",
                ),
            ],
        );
        let i = from_event(&task, &patterns).unwrap();
        assert_eq!(i.data, "powershell.exe -enc AAA");
        assert_eq!(i.level, Level::High);

        let cmd = event(
            1,
            "Microsoft-Windows-Sysmon/Operational",
            &[
                ("Image", r"C:\Windows\System32\schtasks.exe"),
                (
                    "CommandLine",
                    r"schtasks /create /tn x /tr C:\ProgramData\x.exe /sc onlogon",
                ),
            ],
        );
        assert_eq!(
            from_event(&cmd, &patterns).unwrap().mechanism,
            "Scheduled task (command)"
        );

        let reg = event(
            13,
            "Microsoft-Windows-Sysmon/Operational",
            &[
                ("EventType", "SetValue"),
                (
                    "TargetObject",
                    r"HKU\S-1\Software\Microsoft\Windows\CurrentVersion\Run\updater",
                ),
                ("Details", r"C:\Users\bob\AppData\Roaming\u.exe"),
                ("Image", r"C:\Windows\regedit.exe"),
            ],
        );
        let i = from_event(&reg, &patterns).unwrap();
        assert_eq!(
            (i.mechanism.as_str(), i.level.clone()),
            ("Run key", Level::High)
        );

        let benign = event(
            1,
            "Microsoft-Windows-Sysmon/Operational",
            &[("CommandLine", "notepad.exe")],
        );
        assert!(from_event(&benign, &patterns).is_none());
    }

    #[test]
    fn groups_items_into_ranked_findings() {
        let patterns = command_patterns();
        let svc = event(
            7045,
            "System",
            &[
                ("ServiceName", "evil"),
                ("ImagePath", r"C:\Users\Public\evil.exe"),
            ],
        );
        let user = event(
            4720,
            "Security",
            &[("TargetUserName", "backdoor"), ("SubjectUserName", "admin")],
        );
        let items: Vec<Item> = [&svc, &svc, &user]
            .iter()
            .filter_map(|e| from_event(e, &patterns))
            .collect();
        let findings = to_findings(&items);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].title, "Service installed: evil");
        assert_eq!(findings[0].count, 2);
        assert_eq!(findings[1].title, "Account created: backdoor");
    }

    #[test]
    fn reads_user_hive() {
        // The notatin test hives are only present when the dependency was fetched from git.
        let home = std::env::var_os("CARGO_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cargo")));
        let dir = home.map(|h| std::fs::read_dir(h.join("git").join("checkouts")));
        let Some(hive) = dir.and_then(|d| d.ok()).and_then(|d| {
            d.flatten()
                .filter(|e| e.file_name().to_string_lossy().starts_with("notatin"))
                .flat_map(|e| std::fs::read_dir(e.path()).into_iter().flatten().flatten())
                .map(|e| e.path().join("test_data").join("NTUSER.DAT"))
                .find(|p| p.is_file())
        }) else {
            return;
        };
        let items = sweep_hive(
            &Hive {
                path: hive,
                kind: HiveKind::NtUser,
            },
            "PC",
        )
        .unwrap();
        assert!(items.iter().all(|i| i.source.starts_with("registry")));
    }
}
