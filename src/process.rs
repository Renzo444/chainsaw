//! Process drill-down: rebuilds process trees from Sysmon (Event ID 1) and Security (Event ID 4688)
//! process creation events, and follows a process and its children over a timeline of their
//! activity.

use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;

use chrono::{DateTime, Duration, Utc};
use prettytable::{Table, row};
use serde::Serialize;
use serde_json::json;

use crate::events::{self, Event, is_suspicious_path};
use crate::findings::{md_code, md_escape, truncate};
use crate::ioc::{Output, display_paths, window_text};
use crate::window::Window;

/// Sysmon events that describe what a process did.
const SYSMON_ACTIVITY: &[u32] = &[3, 5, 8, 10, 11, 12, 13, 14, 15, 17, 18, 22, 23, 26];

#[derive(Clone, Debug, Serialize)]
pub struct Process {
    pub id: usize,
    pub host: String,
    pub guid: Option<String>,
    pub pid: Option<u64>,
    pub ppid: Option<u64>,
    pub image: String,
    pub command_line: String,
    pub user: String,
    pub started: Option<DateTime<Utc>>,
    pub source: String,
    pub parent: Option<usize>,
    pub children: Vec<usize>,
    /// Whether the process was only inferred from a child's parent fields.
    pub inferred: bool,
}

impl Process {
    pub fn name(&self) -> &str {
        self.image
            .rsplit(['\\', '/'])
            .next()
            .filter(|n| !n.is_empty())
            .unwrap_or(&self.image)
    }

    pub fn suspicious(&self) -> bool {
        is_suspicious_path(&self.image) || is_suspicious_path(&self.command_line)
    }

    fn label(&self) -> String {
        let pid = self.pid.map(|p| format!(" pid {}", p)).unwrap_or_default();
        format!("{}{}", self.name(), pid)
    }
}

fn parse_pid(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
}

#[derive(Default)]
pub struct Forest {
    pub processes: Vec<Process>,
    by_guid: HashMap<(String, String), usize>,
}

impl Forest {
    fn add(&mut self, mut p: Process) -> usize {
        let id = self.processes.len();
        p.id = id;
        if let Some(guid) = &p.guid {
            self.by_guid.insert((p.host.clone(), guid.to_lowercase()), id);
        }
        self.processes.push(p);
        id
    }

    fn link(&mut self, child: usize, parent: usize) {
        if child != parent && self.processes[child].parent.is_none() {
            self.processes[child].parent = Some(parent);
            self.processes[parent].children.push(child);
        }
    }

    /// The most recent process on the host with the pid that started at or before the time.
    fn find_by_pid(&self, host: &str, pid: u64, before: DateTime<Utc>) -> Option<usize> {
        self.processes
            .iter()
            .filter(|p| p.host == host && p.pid == Some(pid))
            .filter(|p| p.started.is_none_or(|s| s <= before))
            .max_by_key(|p| p.started)
            .map(|p| p.id)
    }

    /// Builds the process forest from process creation events, which must be sorted by time.
    pub fn build(events: &[Event]) -> Self {
        let mut forest = Self::default();
        let mut pending: Vec<(usize, &Event)> = vec![];
        for e in events {
            let sysmon = e.is_sysmon() && e.event_id == 1;
            let security = e.is_channel("Security") && e.event_id == 4688;
            if !sysmon && !security {
                continue;
            }
            let (pid, image, user) = if sysmon {
                (e.get("ProcessId"), e.get("Image"), e.get("User"))
            } else {
                (
                    e.get("NewProcessId"),
                    e.get("NewProcessName"),
                    e.get("SubjectUserName"),
                )
            };
            let pid = parse_pid(pid);
            // Prefer the Sysmon record when both sources describe the same process.
            if security
                && let Some(pid) = pid
                && forest.processes.iter().any(|p| {
                    p.host == e.host
                        && p.pid == Some(pid)
                        && p.image.eq_ignore_ascii_case(image)
                        && p.started
                            .is_some_and(|s| (s - e.timestamp).abs() <= Duration::seconds(2))
                })
            {
                continue;
            }
            let id = forest.add(Process {
                id: 0,
                host: e.host.clone(),
                guid: Some(e.get("ProcessGuid").to_string()).filter(|g| !g.is_empty()),
                pid,
                ppid: parse_pid(if sysmon {
                    e.get("ParentProcessId")
                } else {
                    e.get("ProcessId")
                }),
                image: image.to_string(),
                command_line: e.get("CommandLine").to_string(),
                user: user.to_string(),
                started: Some(e.timestamp),
                source: e.label(),
                parent: None,
                children: vec![],
                inferred: false,
            });
            pending.push((id, e));
        }
        for (id, e) in pending {
            let parent_guid = e.get("ParentProcessGuid").to_lowercase();
            let parent = if !parent_guid.is_empty() {
                forest
                    .by_guid
                    .get(&(e.host.clone(), parent_guid.clone()))
                    .copied()
            } else {
                forest.processes[id]
                    .ppid
                    .and_then(|ppid| forest.find_by_pid(&e.host, ppid, e.timestamp))
            };
            let parent = match parent {
                Some(p) => p,
                None => {
                    let image = [e.get("ParentImage"), e.get("ParentProcessName")]
                        .into_iter()
                        .find(|v| !v.is_empty())
                        .unwrap_or("unknown");
                    if image == "unknown" && forest.processes[id].ppid.is_none() {
                        continue;
                    }
                    let parent = forest.add(Process {
                        id: 0,
                        host: e.host.clone(),
                        guid: Some(parent_guid).filter(|g| !g.is_empty()),
                        pid: forest.processes[id].ppid,
                        ppid: None,
                        image: image.to_string(),
                        command_line: e.get("ParentCommandLine").to_string(),
                        user: e.get("ParentUser").to_string(),
                        started: None,
                        source: "inferred".into(),
                        parent: None,
                        children: vec![],
                        inferred: true,
                    });
                    parent
                }
            };
            forest.link(id, parent);
        }
        forest
    }

    pub fn descendants(&self, root: usize, depth: usize) -> Vec<(usize, usize)> {
        let mut out = vec![];
        let mut stack = vec![(root, 0)];
        while let Some((id, d)) = stack.pop() {
            out.push((id, d));
            if d < depth {
                let mut children = self.processes[id].children.clone();
                children.sort_by_key(|c| std::cmp::Reverse(self.processes[*c].started));
                stack.extend(children.into_iter().map(|c| (c, d + 1)));
            }
        }
        out
    }

    pub fn ancestors(&self, id: usize, max: usize) -> Vec<usize> {
        let mut out = vec![];
        let mut current = self.processes[id].parent;
        while let Some(p) = current {
            if out.len() >= max || out.contains(&p) {
                break;
            }
            out.push(p);
            current = self.processes[p].parent;
        }
        out.reverse();
        out
    }
}

/// How to choose the processes to drill into.
#[derive(Clone, Debug, Default)]
pub struct Selector {
    pub names: Vec<String>,
    pub pids: Vec<u64>,
    pub guids: Vec<String>,
    pub host: Option<String>,
}

impl Selector {
    pub fn is_empty(&self) -> bool {
        self.names.is_empty() && self.pids.is_empty() && self.guids.is_empty()
    }

    pub fn matches(&self, p: &Process) -> bool {
        if let Some(host) = &self.host
            && !p.host.to_lowercase().contains(&host.to_lowercase())
        {
            return false;
        }
        let image = p.image.to_lowercase();
        let command_line = p.command_line.to_lowercase();
        self.names.iter().any(|n| {
            let n = n.to_lowercase();
            image.contains(&n) || command_line.contains(&n)
        }) || p.pid.is_some_and(|pid| self.pids.contains(&pid))
            || p.guid.as_ref().is_some_and(|g| {
                self.guids
                    .iter()
                    .any(|s| s.trim_matches(['{', '}']).eq_ignore_ascii_case(g.trim_matches(['{', '}'])))
            })
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct TimelineEntry {
    pub timestamp: DateTime<Utc>,
    pub host: String,
    pub process: String,
    pub event: String,
    pub detail: String,
}

fn describe(e: &Event) -> String {
    let g = |k: &str| e.get(k);
    if e.is_channel("Security") && e.event_id == 4688 {
        return format!("started: {}", g("CommandLine"));
    }
    match e.event_id {
        1 => format!("started: {}", g("CommandLine")),
        3 => {
            let host = g("DestinationHostname");
            format!(
                "network {}: {}:{} -> {}:{}{}",
                g("Protocol"),
                g("SourceIp"),
                g("SourcePort"),
                g("DestinationIp"),
                g("DestinationPort"),
                if host.is_empty() || host == "-" {
                    String::new()
                } else {
                    format!(" ({})", host)
                }
            )
        }
        5 => "terminated".to_string(),
        8 => format!("remote thread into {}", g("TargetImage")),
        10 => format!("accessed {} ({})", g("TargetImage"), g("GrantedAccess")),
        11 => format!("file created: {}", g("TargetFilename")),
        12..=14 => {
            let details = g("Details");
            format!(
                "registry {}: {}{}",
                g("EventType"),
                g("TargetObject"),
                if details.is_empty() {
                    String::new()
                } else {
                    format!(" = {}", details)
                }
            )
        }
        15 => format!("stream created: {}", g("TargetFilename")),
        17 | 18 => format!("pipe: {}", g("PipeName")),
        22 => format!("dns: {} -> {}", g("QueryName"), g("QueryResults")),
        23 | 26 => format!("file deleted: {}", g("TargetFilename")),
        _ => String::new(),
    }
}

pub struct Options {
    pub paths: Vec<PathBuf>,
    pub selector: Selector,
    pub depth: usize,
    pub activity: bool,
    pub window: Window,
    pub output: Output,
    pub skip_errors: bool,
}

struct Drill {
    roots: Vec<usize>,
    /// (process, depth, is ancestor context, is a match)
    lines: Vec<(usize, usize, bool, bool)>,
    timeline: Vec<TimelineEntry>,
    members: BTreeSet<usize>,
}

fn drill(forest: &Forest, events: &[Event], opts: &Options) -> Drill {
    let matched: BTreeSet<usize> = forest
        .processes
        .iter()
        .filter(|p| !p.inferred && opts.selector.matches(p))
        .map(|p| p.id)
        .collect();
    let roots: Vec<usize> = matched
        .iter()
        .copied()
        .filter(|id| {
            !forest
                .ancestors(*id, usize::MAX)
                .iter()
                .any(|a| matched.contains(a))
        })
        .collect();
    let mut lines = vec![];
    let mut members = BTreeSet::new();
    for root in &roots {
        let ancestors = forest.ancestors(*root, 5);
        for (d, a) in ancestors.iter().enumerate() {
            lines.push((*a, d, true, false));
        }
        for (id, d) in forest.descendants(*root, opts.depth) {
            members.insert(id);
            lines.push((id, ancestors.len() + d, false, matched.contains(&id)));
        }
    }

    let mut timeline = vec![];
    let guids: HashMap<(String, String), usize> = members
        .iter()
        .filter_map(|id| {
            let p = &forest.processes[*id];
            p.guid
                .as_ref()
                .map(|g| ((p.host.clone(), g.to_lowercase()), *id))
        })
        .collect();
    for id in &members {
        let p = &forest.processes[*id];
        if let Some(started) = p.started {
            timeline.push(TimelineEntry {
                timestamp: started,
                host: p.host.clone(),
                process: p.label(),
                event: p.source.clone(),
                detail: format!("started: {}", p.command_line),
            });
        }
    }
    if opts.activity {
        for e in events.iter().filter(|e| e.is_sysmon() && e.event_id != 1) {
            let guid = [e.get("ProcessGuid"), e.get("SourceProcessGuid")]
                .into_iter()
                .find(|g| !g.is_empty())
                .unwrap_or("")
                .to_lowercase();
            if let Some(id) = guids.get(&(e.host.clone(), guid)) {
                timeline.push(TimelineEntry {
                    timestamp: e.timestamp,
                    host: e.host.clone(),
                    process: forest.processes[*id].label(),
                    event: e.label(),
                    detail: describe(e),
                });
            }
        }
    }
    timeline.sort_by_key(|t| t.timestamp);
    Drill {
        roots,
        lines,
        timeline,
        members,
    }
}

fn tree_text(forest: &Forest, d: &Drill) -> String {
    let mut out = String::new();
    for (i, (id, depth, context, matched)) in d.lines.iter().enumerate() {
        let p = &forest.processes[*id];
        if *depth == 0 && i > 0 {
            out.push('\n');
        }
        let indent = if *depth == 0 {
            String::new()
        } else {
            format!("{}└─ ", "   ".repeat(depth - 1))
        };
        let time = p
            .started
            .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_else(|| "????-??-?? ??:??:??".to_string());
        let mut line = format!("{}{} {} [{}]", indent, time, p.label(), p.host);
        if !p.user.is_empty() {
            line.push_str(&format!(" {}", p.user));
        }
        if !p.command_line.is_empty() {
            line.push_str(&format!("  {}", truncate(&p.command_line, 160)));
        }
        if *matched {
            line.push_str("  ◀ match");
        } else if *context {
            line.push_str("  (parent)");
        }
        if p.suspicious() && !*context {
            line.push_str("  ⚠ suspicious");
        }
        out.push_str(&line);
        out.push('\n');
    }
    out
}

pub fn run(opts: Options) -> crate::Result<()> {
    if opts.selector.is_empty() {
        anyhow::bail!("Choose the process to drill into with --name, --pid or --guid");
    }
    let files = events::evtx_files(&opts.paths, opts.skip_errors)?;
    if files.is_empty() {
        anyhow::bail!("No event log files were found in the provided paths");
    }
    cs_eprintln!(
        "[+] Building process trees from {} event logs ({})",
        files.len(),
        window_text(&opts.window).to_lowercase()
    );
    let events = events::load(&files, &opts.window, opts.skip_errors, |e| {
        (e.is_sysmon() && (e.event_id == 1 || SYSMON_ACTIVITY.contains(&e.event_id)))
            || (e.is_channel("Security") && e.event_id == 4688)
    })?;
    let forest = Forest::build(&events);
    let created = forest.processes.iter().filter(|p| !p.inferred).count();
    cs_eprintln!("[+] Loaded {} process creation events", created);
    if created == 0 {
        cs_eyellowln!(
            "[!] No process creation events found; this needs Sysmon Event ID 1 or Security Event ID 4688 logs"
        );
    }
    let d = drill(&forest, &events, &opts);
    let processes: Vec<&Process> = d.members.iter().map(|id| &forest.processes[*id]).collect();

    match opts.output {
        Output::Json => {
            cs_print_json!(&json!({
                "matches": d.roots.iter().map(|id| &forest.processes[*id]).collect::<Vec<_>>(),
                "processes": processes,
                "timeline": d.timeline,
            }))?;
        }
        Output::Markdown => {
            let mut md = String::from("# Chainsaw process drill-down\n\n| | |\n| --- | --- |\n");
            md.push_str(&format!(
                "| Generated | {} |\n| Evidence | {} |\n| Time window | {} |\n| Selection | {} |\n| Matching trees | {} |\n| Processes | {} |\n",
                Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
                md_escape(&display_paths(&opts.paths)),
                window_text(&opts.window),
                md_escape(&describe_selector(&opts.selector)),
                d.roots.len(),
                d.members.len()
            ));
            md.push_str("\n## Process tree\n\n");
            if d.lines.is_empty() {
                md.push_str("No matching processes.\n");
            } else {
                md.push_str("Lines marked `(parent)` show how the match was launched; `⚠ suspicious` marks user-writable paths or living-off-the-land binaries.\n\n```text\n");
                md.push_str(&tree_text(&forest, &d));
                md.push_str("```\n");
            }
            md.push_str("\n## Timeline\n\n");
            if d.timeline.is_empty() {
                md.push_str("No activity.\n");
            } else {
                md.push_str("| Time (UTC) | Host | Process | Event | Detail |\n| --- | --- | --- | --- | --- |\n");
                for t in &d.timeline {
                    md.push_str(&format!(
                        "| {} | {} | {} | {} | {} |\n",
                        t.timestamp.format("%Y-%m-%d %H:%M:%S"),
                        md_escape(&t.host),
                        md_escape(&t.process),
                        md_escape(&t.event),
                        md_code(&truncate(&t.detail, 240))
                    ));
                }
            }
            cs_print!("{}", md);
        }
        Output::Std => {
            if d.lines.is_empty() {
                cs_eprintln!("[+] No processes matched {}", describe_selector(&opts.selector));
            } else {
                cs_eprintln!(
                    "[+] {} matching process trees ({} processes):\n",
                    d.roots.len(),
                    d.members.len()
                );
                cs_print!("{}", tree_text(&forest, &d));
                if !d.timeline.is_empty() {
                    cs_eprintln!("\n[+] Timeline of the processes and their children:");
                    let mut table = Table::new();
                    table.set_format(crate::cli::table_format());
                    table.set_titles(row!["timestamp (UTC)", "host", "process", "event", "detail"]);
                    for t in &d.timeline {
                        table.add_row(row![
                            t.timestamp.format("%Y-%m-%d %H:%M:%S"),
                            t.host,
                            t.process,
                            t.event,
                            truncate(&t.detail, 120)
                        ]);
                    }
                    cs_print_table!(table);
                }
            }
        }
    }
    Ok(())
}

fn describe_selector(s: &Selector) -> String {
    let mut parts = vec![];
    if !s.names.is_empty() {
        parts.push(format!("name: {}", s.names.join(", ")));
    }
    if !s.pids.is_empty() {
        parts.push(format!(
            "pid: {}",
            s.pids.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ")
        ));
    }
    if !s.guids.is_empty() {
        parts.push(format!("guid: {}", s.guids.join(", ")));
    }
    if let Some(h) = &s.host {
        parts.push(format!("host: {}", h));
    }
    parts.join("; ")
}

pub fn parse_pid_arg(s: &str) -> Result<u64, String> {
    parse_pid(s).ok_or_else(|| format!("invalid pid '{}'", s))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn event(id: u32, channel: &str, secs: i64, fields: &[(&str, &str)]) -> Event {
        Event {
            timestamp: DateTime::from_timestamp(1_600_000_000 + secs, 0).unwrap(),
            host: "PC".into(),
            channel: channel.into(),
            provider: String::new(),
            event_id: id,
            record_id: secs as u64,
            fields: fields
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<BTreeMap<_, _>>(),
            file: PathBuf::new(),
        }
    }

    const SYSMON: &str = "Microsoft-Windows-Sysmon/Operational";

    fn sample() -> Vec<Event> {
        vec![
            event(1, SYSMON, 0, &[
                ("ProcessGuid", "{A}"), ("ProcessId", "100"), ("Image", r"C:\Windows\explorer.exe"),
                ("ParentProcessGuid", "{ROOT}"), ("ParentProcessId", "4"), ("ParentImage", r"C:\Windows\userinit.exe"),
            ]),
            event(1, SYSMON, 10, &[
                ("ProcessGuid", "{B}"), ("ProcessId", "200"), ("Image", r"C:\Windows\System32\cmd.exe"),
                ("CommandLine", "cmd.exe /c evil.bat"), ("ParentProcessGuid", "{A}"), ("ParentProcessId", "100"),
            ]),
            event(1, SYSMON, 20, &[
                ("ProcessGuid", "{C}"), ("ProcessId", "300"), ("Image", r"C:\Users\Public\evil.exe"),
                ("CommandLine", r"C:\Users\Public\evil.exe"), ("ParentProcessGuid", "{B}"), ("ParentProcessId", "200"),
            ]),
            event(22, SYSMON, 25, &[("ProcessGuid", "{C}"), ("QueryName", "c2.example.com"), ("QueryResults", "1.2.3.4")]),
            event(3, SYSMON, 26, &[("ProcessGuid", "{C}"), ("DestinationIp", "1.2.3.4"), ("DestinationPort", "443")]),
            event(4688, "Security", 30, &[
                ("NewProcessId", "0x190"), ("NewProcessName", r"C:\Windows\System32\whoami.exe"),
                ("ProcessId", "0x12c"), ("CommandLine", "whoami /all"),
            ]),
            event(4688, "Security", 40, &[
                ("NewProcessId", "0x12c"), ("NewProcessName", r"C:\Users\Public\evil.exe"),
                ("ProcessId", "0xc8"),
            ]),
        ]
    }

    #[test]
    fn builds_trees_across_sources() {
        let events = sample();
        let forest = Forest::build(&events);
        let by_name = |n: &str| forest.processes.iter().find(|p| p.name() == n).unwrap();
        let evil = by_name("evil.exe");
        let whoami = by_name("whoami.exe");
        // The Security 4688 duplicate of evil.exe is not a separate process (it is 20s later, so
        // it is kept), but whoami (pid 0x190 = 400) is a child of the Sysmon evil.exe (pid 300).
        assert_eq!(whoami.pid, Some(400));
        assert_eq!(whoami.parent, Some(evil.id));
        assert_eq!(forest.processes[by_name("cmd.exe").parent.unwrap()].name(), "explorer.exe");
        let userinit = by_name("userinit.exe");
        assert!(userinit.inferred);
    }

    #[test]
    fn drills_into_children_with_activity() {
        let events = sample();
        let forest = Forest::build(&events);
        let opts = Options {
            paths: vec![],
            selector: Selector {
                names: vec!["cmd.exe".into()],
                ..Default::default()
            },
            depth: 10,
            activity: true,
            window: Window::default(),
            output: Output::Std,
            skip_errors: false,
        };
        let d = drill(&forest, &events, &opts);
        assert_eq!(d.roots.len(), 1);
        let names: Vec<&str> = d.members.iter().map(|i| forest.processes[*i].name()).collect();
        assert!(names.contains(&"cmd.exe") && names.contains(&"evil.exe") && names.contains(&"whoami.exe"));
        assert!(!names.contains(&"explorer.exe"));
        let details: Vec<&str> = d.timeline.iter().map(|t| t.detail.as_str()).collect();
        assert!(details.contains(&"dns: c2.example.com -> 1.2.3.4"));
        assert!(details.iter().any(|d| d.starts_with("network")));
        let tree = tree_text(&forest, &d);
        assert!(tree.contains("explorer.exe pid 100 [PC]  (parent)"), "{}", tree);
        assert!(tree.contains("◀ match"));
        assert!(tree.contains("⚠ suspicious"));
    }

    #[test]
    fn parses_pids() {
        assert_eq!(parse_pid("0x1a"), Some(26));
        assert_eq!(parse_pid("26"), Some(26));
        assert_eq!(parse_pid("x"), None);
    }
}
