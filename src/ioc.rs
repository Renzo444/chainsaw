//! Sweeps event logs for indicators of compromise: process names, file hashes, IP addresses,
//! domain names and free text.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use prettytable::{Table, row};
use serde::Serialize;
use serde_json::json;

use crate::events::{self, Event};
use crate::findings::{self, Evidence, Finding, Report, md_code, md_escape, truncate};
use crate::rule::Level;
use crate::window::Window;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IocKind {
    Hash,
    Ip,
    Domain,
    Process,
    Keyword,
}

impl IocKind {
    fn name(&self) -> &'static str {
        match self {
            IocKind::Hash => "hash",
            IocKind::Ip => "ip",
            IocKind::Domain => "domain",
            IocKind::Process => "process/file",
            IocKind::Keyword => "keyword",
        }
    }

    fn default_level(&self) -> Level {
        match self {
            IocKind::Hash => Level::Critical,
            IocKind::Ip | IocKind::Domain | IocKind::Process => Level::High,
            IocKind::Keyword => Level::Medium,
        }
    }

    fn tactics(&self) -> Vec<String> {
        match self {
            IocKind::Ip | IocKind::Domain => vec!["command_and_control".into()],
            IocKind::Hash | IocKind::Process => vec!["execution".into()],
            IocKind::Keyword => vec![],
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Ioc {
    pub value: String,
    pub kind: IocKind,
    pub level: Level,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

const FILE_EXTENSIONS: &[&str] = &[
    "exe", "dll", "sys", "ps1", "psm1", "bat", "cmd", "vbs", "vbe", "js", "jse", "hta", "scr",
    "msi", "lnk", "jar", "py", "sh", "cpl", "ocx",
];

/// Works out what kind of indicator a value is.
pub fn classify(value: &str) -> IocKind {
    let v = value.trim();
    let hex = !v.is_empty() && v.chars().all(|c| c.is_ascii_hexdigit());
    if hex && matches!(v.len(), 32 | 40 | 64) {
        return IocKind::Hash;
    }
    if v.parse::<IpAddr>().is_ok() {
        return IocKind::Ip;
    }
    if v.contains('\\') || v.contains('/') {
        return IocKind::Process;
    }
    if let Some((_, ext)) = v.rsplit_once('.')
        && FILE_EXTENSIONS.contains(&ext.to_lowercase().as_str())
    {
        return IocKind::Process;
    }
    let labels: Vec<&str> = v.split('.').collect();
    if labels.len() >= 2
        && labels.iter().all(|l| {
            !l.is_empty() && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
        && labels
            .last()
            .is_some_and(|tld| tld.len() >= 2 && tld.chars().all(|c| c.is_ascii_alphabetic()))
    {
        return IocKind::Domain;
    }
    IocKind::Keyword
}

fn parse_level(s: &str) -> Option<Level> {
    match s.trim().to_lowercase().as_str() {
        "critical" => Some(Level::Critical),
        "high" => Some(Level::High),
        "medium" => Some(Level::Medium),
        "low" => Some(Level::Low),
        "info" | "informational" => Some(Level::Info),
        _ => None,
    }
}

/// Parses an indicator line: `value[,severity[,note]]`. Blank lines and `#` comments are
/// ignored. Defanged values such as `evil[.]com` or `hxxp://` are refanged.
pub fn parse_line(line: &str) -> Option<Ioc> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let mut parts = line.splitn(3, ',');
    let value = parts
        .next()?
        .trim()
        .trim_matches('"')
        .replace("[.]", ".")
        .replace("(.)", ".")
        .replace("[:]", ":")
        .replace("hxxp", "http");
    if value.is_empty() {
        return None;
    }
    let kind = classify(&value);
    let level = parts
        .next()
        .and_then(parse_level)
        .unwrap_or_else(|| kind.default_level());
    let note = parts
        .next()
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty());
    Some(Ioc {
        value,
        kind,
        level,
        note,
    })
}

pub fn load_file(path: &Path) -> crate::Result<Vec<Ioc>> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| anyhow!("could not read IOC file '{}' - {}", path.display(), e))?;
    Ok(contents.lines().filter_map(parse_line).collect())
}

#[derive(Clone, Debug, Serialize)]
pub struct Hit {
    pub ioc: String,
    pub kind: IocKind,
    pub field: String,
    pub value: String,
    pub event: Event,
}

pub struct Sweeper {
    iocs: Vec<Ioc>,
    matcher: AhoCorasick,
}

impl Sweeper {
    pub fn new(iocs: Vec<Ioc>) -> crate::Result<Self> {
        let matcher = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::Standard)
            .build(iocs.iter().map(|i| i.value.as_str()))?;
        Ok(Self { iocs, matcher })
    }

    pub fn iocs(&self) -> &[Ioc] {
        &self.iocs
    }

    /// Returns the indicators found in the event, as (indicator index, field name).
    pub fn matches(&self, event: &Event) -> Vec<(usize, String)> {
        let mut found: Vec<(usize, String)> = vec![];
        for (field, text) in &event.fields {
            for m in self.matcher.find_overlapping_iter(text) {
                let ioc = m.pattern().as_usize();
                let bounded = self.iocs[ioc].kind == IocKind::Keyword || {
                    let before = text[..m.start()].chars().next_back();
                    let after = text[m.end()..].chars().next();
                    !before.is_some_and(|c| c.is_alphanumeric())
                        && !after.is_some_and(|c| c.is_alphanumeric())
                };
                if bounded && !found.iter().any(|(i, f)| *i == ioc && f == field) {
                    found.push((ioc, field.clone()));
                }
            }
        }
        found
    }
}

/// The process involved in a Sysmon event, used to pivot from an indicator to a process tree.
fn process_of(event: &Event) -> Option<(String, String)> {
    let image = ["Image", "SourceImage", "NewProcessName", "ProcessName"]
        .iter()
        .map(|f| event.get(f))
        .find(|v| !v.is_empty())?;
    let guid = ["ProcessGuid", "SourceProcessGuid"]
        .iter()
        .map(|f| event.get(f))
        .find(|v| !v.is_empty())
        .unwrap_or("");
    Some((image.to_string(), guid.to_string()))
}

pub fn sweep(
    sweeper: &Sweeper,
    files: &[PathBuf],
    window: &Window,
    skip_errors: bool,
) -> crate::Result<Vec<Hit>> {
    let events = events::load(files, window, skip_errors, |e| !sweeper.matches(e).is_empty())?;
    let mut hits = vec![];
    for event in events {
        for (ioc, field) in sweeper.matches(&event) {
            let ioc = &sweeper.iocs()[ioc];
            hits.push(Hit {
                ioc: ioc.value.clone(),
                kind: ioc.kind,
                value: event.get(&field).to_string(),
                field,
                event: event.clone(),
            });
        }
    }
    Ok(hits)
}

pub fn to_findings(iocs: &[Ioc], hits: &[Hit]) -> Vec<Finding> {
    let mut by_ioc: BTreeMap<&str, Finding> = BTreeMap::new();
    for hit in hits {
        let ioc = iocs
            .iter()
            .find(|i| i.value == hit.ioc)
            .expect("hit has an indicator");
        let finding = by_ioc.entry(&ioc.value).or_insert_with(|| {
            let mut f = Finding::new(
                &format!("IOC {} ({})", ioc.value, ioc.kind.name()),
                ioc.level.clone(),
                "IOC sweep",
                "ioc",
            );
            f.tactics = ioc.kind.tactics();
            f.description = ioc.note.clone();
            f
        });
        let mut detail = format!("{}: {}", hit.field, truncate(&hit.value, 160));
        if let Some((image, _)) = process_of(&hit.event)
            && !detail.contains(&image)
        {
            detail.push_str(&format!(" (process: {})", image));
        }
        finding.add(Evidence {
            timestamp: Some(hit.event.timestamp),
            host: hit.event.host.clone(),
            event: hit.event.label(),
            detail,
        });
    }
    let mut findings: Vec<Finding> = by_ioc.into_values().collect();
    findings::rank(&mut findings);
    findings
}

#[derive(Clone, Copy, PartialEq)]
pub enum Output {
    Std,
    Json,
    Markdown,
}

pub struct Options {
    pub paths: Vec<PathBuf>,
    pub iocs: Vec<Ioc>,
    pub window: Window,
    pub output: Output,
    pub skip_errors: bool,
}

/// Lists the processes linked to indicator hits so an analyst can pivot to `process`.
fn linked_processes(hits: &[Hit]) -> Vec<(String, String, String, usize)> {
    let mut seen: BTreeMap<(String, String, String), usize> = BTreeMap::new();
    for hit in hits {
        if let Some((image, guid)) = process_of(&hit.event) {
            *seen
                .entry((hit.event.host.clone(), image, guid))
                .or_default() += 1;
        }
    }
    seen.into_iter()
        .map(|((host, image, guid), n)| (host, image, guid, n))
        .collect()
}

pub fn run(opts: Options) -> crate::Result<()> {
    if opts.iocs.is_empty() {
        anyhow::bail!("No indicators were provided, use --ioc or --ioc-file");
    }
    let files = events::evtx_files(&opts.paths, opts.skip_errors)?;
    if files.is_empty() {
        anyhow::bail!("No event log files were found in the provided paths");
    }
    cs_eprintln!(
        "[+] Sweeping {} event logs for {} indicators ({})",
        files.len(),
        opts.iocs.len(),
        if opts.window.is_open() {
            "all time".to_string()
        } else {
            opts.window.describe()
        }
    );
    let sweeper = Sweeper::new(opts.iocs.clone())?;
    let hits = sweep(&sweeper, &files, &opts.window, opts.skip_errors)?;
    let findings = to_findings(&opts.iocs, &hits);
    let processes = linked_processes(&hits);
    let missed: Vec<&Ioc> = opts
        .iocs
        .iter()
        .filter(|i| !hits.iter().any(|h| h.ioc == i.value))
        .collect();

    match opts.output {
        Output::Json => {
            cs_print_json!(&json!({
                "findings": findings,
                "hits": hits,
                "not_found": missed,
            }))?;
        }
        Output::Markdown => {
            let mut sections = vec![];
            if !processes.is_empty() {
                let mut body = String::from(
                    "Pivot into any of these with `chainsaw process <evidence> --guid <ProcessGuid>`.\n\n| Host | Process | ProcessGuid | Hits |\n| --- | --- | --- | --- |\n",
                );
                for (host, image, guid, n) in &processes {
                    body.push_str(&format!(
                        "| {} | {} | {} | {} |\n",
                        md_escape(host),
                        md_code(image),
                        md_code(guid),
                        n
                    ));
                }
                sections.push(("Processes linked to indicators".to_string(), body));
            }
            if !missed.is_empty() {
                let body = missed
                    .iter()
                    .map(|i| format!("- {} ({})", md_code(&i.value), i.kind.name()))
                    .collect::<Vec<_>>()
                    .join("\n");
                sections.push(("Indicators not found".to_string(), body));
            }
            let report = Report {
                title: "Chainsaw IOC sweep".to_string(),
                meta: vec![
                    ("Evidence".to_string(), display_paths(&opts.paths)),
                    ("Time window".to_string(), window_text(&opts.window)),
                    ("Indicators".to_string(), opts.iocs.len().to_string()),
                    ("Event logs".to_string(), files.len().to_string()),
                ],
                findings,
                sections,
            };
            cs_print!("{}", report.to_markdown());
        }
        Output::Std => {
            if hits.is_empty() {
                cs_eprintln!("[+] None of the indicators were found");
            } else {
                let mut table = Table::new();
                table.set_format(crate::cli::table_format());
                table.set_titles(row![
                    "timestamp (UTC)",
                    "host",
                    "event",
                    "indicator",
                    "field",
                    "value"
                ]);
                for hit in &hits {
                    table.add_row(row![
                        hit.event.timestamp.format("%Y-%m-%d %H:%M:%S"),
                        hit.event.host,
                        hit.event.label(),
                        hit.ioc,
                        hit.field,
                        truncate(&hit.value, 80)
                    ]);
                }
                cs_print_table!(table);
                cs_eprintln!("\n[+] Indicators ranked by severity and impact:");
                findings::print_table(&findings);
                if !processes.is_empty() {
                    cs_eprintln!(
                        "\n[+] Processes linked to indicators (pivot with `chainsaw process <evidence> --guid <ProcessGuid>`):"
                    );
                    let mut table = Table::new();
                    table.set_format(crate::cli::table_format());
                    table.set_titles(row!["host", "process", "process guid", "hits"]);
                    for (host, image, guid, n) in &processes {
                        table.add_row(row![host, image, guid, n]);
                    }
                    cs_print_table!(table);
                }
            }
            if !missed.is_empty() {
                cs_eprintln!(
                    "[+] Not found: {}",
                    missed
                        .iter()
                        .map(|i| i.value.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
        }
    }
    cs_eprintln!(
        "[+] {} hits for {} of {} indicators",
        hits.len(),
        opts.iocs.len() - missed.len(),
        opts.iocs.len()
    );
    Ok(())
}

pub fn display_paths(paths: &[PathBuf]) -> String {
    paths
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn window_text(window: &Window) -> String {
    if window.is_open() {
        "All time".to_string()
    } else {
        window.describe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn classifies_indicators() {
        assert_eq!(classify("d41d8cd98f00b204e9800998ecf8427e"), IocKind::Hash);
        assert_eq!(
            classify("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            IocKind::Hash
        );
        assert_eq!(classify("10.1.2.3"), IocKind::Ip);
        assert_eq!(classify("fe80::1"), IocKind::Ip);
        assert_eq!(classify("evil-domain.co.uk"), IocKind::Domain);
        assert_eq!(classify("mimikatz.exe"), IocKind::Process);
        assert_eq!(classify(r"C:\Temp\x.bin"), IocKind::Process);
        assert_eq!(classify("Invoke-Mimikatz"), IocKind::Keyword);
    }

    #[test]
    fn parses_lines() {
        assert!(parse_line("# comment").is_none());
        let i = parse_line("evil[.]com, critical, C2 from the phishing email").unwrap();
        assert_eq!(i.value, "evil.com");
        assert_eq!(i.kind, IocKind::Domain);
        assert_eq!(i.level, Level::Critical);
        assert_eq!(i.note.as_deref(), Some("C2 from the phishing email"));
        assert_eq!(parse_line("1.2.3.4").unwrap().level, Level::High);
    }

    fn event(fields: &[(&str, &str)]) -> Event {
        Event {
            timestamp: Utc::now(),
            host: "PC".into(),
            channel: "Microsoft-Windows-Sysmon/Operational".into(),
            provider: String::new(),
            event_id: 22,
            record_id: 1,
            fields: fields
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            file: PathBuf::new(),
        }
    }

    #[test]
    fn matches_on_boundaries() {
        let iocs = ["evil.com", "10.0.0.1", "MIMIKATZ.EXE", "invoke-"]
            .iter()
            .filter_map(|v| parse_line(v))
            .collect();
        let sweeper = Sweeper::new(iocs).unwrap();
        let m = |fields: &[(&str, &str)]| sweeper.matches(&event(fields));
        assert_eq!(m(&[("QueryName", "cdn.evil.com")]), vec![(0, "QueryName".into())]);
        assert!(m(&[("QueryName", "notevil.com")]).is_empty());
        assert!(m(&[("DestinationIp", "10.0.0.15")]).is_empty());
        assert_eq!(m(&[("DestinationIp", "10.0.0.1")]).len(), 1);
        assert_eq!(m(&[("Image", r"C:\Temp\mimikatz.exe")]).len(), 1);
        assert_eq!(m(&[("ScriptBlockText", "Invoke-Thing")]).len(), 1);
    }
}
