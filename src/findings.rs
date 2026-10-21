//! Findings ranked by severity and impact, shared by the hunt, IOC, process and persistence
//! analyses, along with their table and Markdown renderings.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use prettytable::{Table, row};
use serde::Serialize;
use serde_json::Value as Json;

use crate::rule::Level;

/// The number of evidence entries kept per finding.
const MAX_EVIDENCE: usize = 10;

#[derive(Clone, Debug, Serialize)]
pub struct Evidence {
    pub timestamp: Option<DateTime<Utc>>,
    pub host: String,
    pub event: String,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Finding {
    pub rank: usize,
    pub score: u32,
    pub level: Level,
    pub title: String,
    pub category: String,
    pub source: String,
    pub tactics: Vec<String>,
    pub techniques: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub count: usize,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    pub hosts: BTreeSet<String>,
    pub evidence: Vec<Evidence>,
}

impl Finding {
    pub fn new(title: &str, level: Level, category: &str, source: &str) -> Self {
        Self {
            rank: 0,
            score: 0,
            level,
            title: title.to_string(),
            category: category.to_string(),
            source: source.to_string(),
            tactics: vec![],
            techniques: vec![],
            description: None,
            count: 0,
            first_seen: None,
            last_seen: None,
            hosts: BTreeSet::new(),
            evidence: vec![],
        }
    }

    pub fn add(&mut self, evidence: Evidence) {
        self.count += 1;
        if let Some(t) = evidence.timestamp {
            self.first_seen = Some(self.first_seen.map_or(t, |f| f.min(t)));
            self.last_seen = Some(self.last_seen.map_or(t, |l| l.max(t)));
        }
        if !evidence.host.is_empty() {
            self.hosts.insert(evidence.host.clone());
        }
        // Keep the earliest evidence, as that is where an investigation usually starts.
        self.evidence.push(evidence);
        if self.evidence.len() > MAX_EVIDENCE {
            self.evidence.sort_by_key(|e| e.timestamp);
            self.evidence.truncate(MAX_EVIDENCE);
        }
    }
}

pub fn level_weight(level: &Level) -> u32 {
    match level {
        Level::Critical => 100,
        Level::High => 70,
        Level::Medium => 40,
        Level::Low => 15,
        Level::Info => 5,
    }
}

/// How damaging activity in a MITRE ATT&CK tactic usually is, used to rank findings of the same
/// severity.
pub fn tactic_weight(tactic: &str) -> u32 {
    match tactic {
        "impact" => 30,
        "exfiltration" | "credential_access" => 25,
        "lateral_movement" => 20,
        "privilege_escalation" => 18,
        "persistence" | "command_and_control" => 15,
        "defense_evasion" => 12,
        "execution" | "collection" | "initial_access" => 10,
        "discovery" => 4,
        _ => 2,
    }
}

const TACTICS: &[&str] = &[
    "reconnaissance",
    "resource_development",
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "command_and_control",
    "exfiltration",
    "impact",
];

/// Splits Sigma style tags (`attack.persistence`, `attack.t1543.003`) into tactics and
/// techniques.
pub fn parse_tags(tags: &[String]) -> (Vec<String>, Vec<String>) {
    let mut tactics = vec![];
    let mut techniques = vec![];
    for tag in tags {
        let tag = tag.to_lowercase().replace('-', "_");
        let Some(name) = tag.strip_prefix("attack.") else {
            continue;
        };
        if TACTICS.contains(&name) {
            if !tactics.iter().any(|t| t == name) {
                tactics.push(name.to_string());
            }
        } else if name.starts_with('t') && name[1..].starts_with(|c: char| c.is_ascii_digit()) {
            let technique = name.to_uppercase();
            if !techniques.contains(&technique) {
                techniques.push(technique);
            }
        }
    }
    (tactics, techniques)
}

/// Infers tactics from a Chainsaw rule group name.
pub fn group_tactics(group: &str) -> Vec<String> {
    let group = group.to_lowercase();
    let tactic = if group.contains("credential") || group.contains("login attack") {
        "credential_access"
    } else if group.contains("lateral") || group.contains("rdp") {
        "lateral_movement"
    } else if group.contains("persistence") || group.contains("service installation") {
        "persistence"
    } else if group.contains("tampering")
        || group.contains("evasion")
        || group.contains("indicator removal")
        || group.contains("antivirus")
    {
        "defense_evasion"
    } else if group.contains("powershell") {
        "execution"
    } else {
        return vec![];
    };
    vec![tactic.to_string()]
}

/// Scores, sorts and numbers the findings, most important first.
pub fn rank(findings: &mut [Finding]) {
    for f in findings.iter_mut() {
        let tactic = f
            .tactics
            .iter()
            .map(|t| tactic_weight(t))
            .max()
            .unwrap_or(0);
        let spread = (f.hosts.len().saturating_sub(1) as u32 * 5).min(20);
        f.score = level_weight(&f.level) + tactic + spread;
    }
    findings.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then(b.count.cmp(&a.count))
            .then(a.first_seen.cmp(&b.first_seen))
            .then(a.title.cmp(&b.title))
    });
    for (i, f) in findings.iter_mut().enumerate() {
        f.rank = i + 1;
    }
}

fn get<'a>(json: &'a Json, path: &[&str]) -> Option<&'a Json> {
    let mut json = json;
    for p in path {
        json = json.get(p)?;
    }
    Some(json)
}

pub fn as_text(json: &Json) -> String {
    match json {
        Json::String(s) => s.clone(),
        Json::Null => String::new(),
        Json::Object(o) if o.contains_key("#text") => as_text(&o["#text"]),
        other => other.to_string(),
    }
}

/// Fields worth showing to describe an event, in order of preference.
const DETAIL_FIELDS: &[&str] = &[
    "CommandLine",
    "Image",
    "TargetObject",
    "Details",
    "ServiceName",
    "ImagePath",
    "ServiceFileName",
    "TaskName",
    "QueryName",
    "DestinationIp",
    "DestinationHostname",
    "TargetFilename",
    "ScriptBlockText",
    "TargetUserName",
    "SubjectUserName",
    "IpAddress",
    "FileName",
];

/// Summarises an event log record (or other document) as host, event label and detail.
pub fn summarise(data: &Json) -> (String, String, String) {
    if let Some(system) = get(data, &["Event", "System"]) {
        let host = system.get("Computer").map(as_text).unwrap_or_default();
        let id = system.get("EventID").map(as_text).unwrap_or_default();
        let channel = system.get("Channel").map(as_text).unwrap_or_default();
        let event = if channel.is_empty() {
            format!("EID {}", id)
        } else {
            format!("{} {}", channel, id)
        };
        let fields = get(data, &["Event", "EventData"])
            .or_else(|| get(data, &["Event", "UserData"]))
            .cloned()
            .unwrap_or(Json::Null);
        let mut flat = BTreeMap::new();
        flatten(&fields, &mut flat);
        let detail = DETAIL_FIELDS
            .iter()
            .filter_map(|k| {
                flat.get(*k)
                    .filter(|v| !v.is_empty())
                    .map(|v| format!("{}: {}", k, v))
            })
            .take(2)
            .collect::<Vec<_>>()
            .join("; ");
        return (host, event, truncate(&detail, 240));
    }
    (
        String::new(),
        String::new(),
        truncate(&data.to_string(), 240),
    )
}

/// Flattens nested objects into leaf name to text, keeping the first value seen for a name.
pub fn flatten(json: &Json, out: &mut BTreeMap<String, String>) {
    if let Json::Object(map) = json {
        for (k, v) in map {
            match v {
                Json::Object(o) if !o.contains_key("#text") => flatten(v, out),
                _ => {
                    out.entry(k.trim_end_matches("_attributes").to_string())
                        .or_insert_with(|| as_text(v));
                }
            }
        }
    }
}

pub fn truncate(s: &str, max: usize) -> String {
    let s = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if s.chars().count() <= max {
        s
    } else {
        format!("{}…", s.chars().take(max).collect::<String>())
    }
}

/// Groups the serialised hunt detections into one finding per rule.
pub fn from_detections(detections: &[Json]) -> Vec<Finding> {
    let mut findings: BTreeMap<(String, String), Finding> = BTreeMap::new();
    for d in detections {
        let name = d.get("name").map(as_text).unwrap_or_default();
        let source = d.get("source").map(as_text).unwrap_or_default();
        let group = d.get("group").map(as_text).unwrap_or_default();
        let level = d
            .get("level")
            .and_then(|l| serde_json::from_value::<Level>(l.clone()).ok())
            .unwrap_or(Level::Info);
        let finding = findings
            .entry((source.clone(), name.clone()))
            .or_insert_with(|| {
                let mut f = Finding::new(&name, level, &group, &source);
                let tags: Vec<String> = d
                    .get("tags")
                    .and_then(|t| serde_json::from_value(t.clone()).ok())
                    .unwrap_or_default();
                let (tactics, techniques) = parse_tags(&tags);
                f.tactics = if tactics.is_empty() {
                    group_tactics(&group)
                } else {
                    tactics
                };
                f.techniques = techniques;
                f
            });
        let timestamp = d
            .get("timestamp")
            .and_then(|t| t.as_str())
            .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
            .map(|t| t.with_timezone(&Utc));
        let data = d
            .get("document")
            .or_else(|| d.get("documents").and_then(|ds| ds.get(0)))
            .and_then(|doc| doc.get("data"))
            .cloned()
            .unwrap_or(Json::Null);
        let (host, event, detail) = summarise(&data);
        finding.add(Evidence {
            timestamp,
            host,
            event,
            detail,
        });
    }
    let mut findings: Vec<Finding> = findings.into_values().collect();
    rank(&mut findings);
    findings
}

pub fn fmt_time(t: &Option<DateTime<Utc>>) -> String {
    t.map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| "-".to_string())
}

fn plural(n: usize, word: &str) -> String {
    format!("{} {}{}", n, word, if n == 1 { "" } else { "s" })
}

fn capitalise(s: &str) -> String {
    let mut c = s.chars();
    c.next()
        .map(|f| f.to_uppercase().chain(c).collect())
        .unwrap_or_default()
}

fn attack(f: &Finding) -> String {
    let mut parts: Vec<String> = f.tactics.clone();
    parts.extend(f.techniques.iter().cloned());
    parts.join(", ")
}

fn hosts(f: &Finding, max: usize) -> String {
    let mut hosts: Vec<&str> = f.hosts.iter().map(|h| h.as_str()).take(max).collect();
    if f.hosts.len() > max {
        hosts.push("…");
    }
    hosts.join(", ")
}

/// Prints the ranked findings as a table.
pub fn print_table(findings: &[Finding]) {
    let mut table = Table::new();
    table.set_format(crate::cli::table_format());
    table.set_titles(row![
        "#",
        "severity",
        "score",
        "finding",
        "att&ck",
        "hits",
        "hosts",
        "first seen (UTC)",
        "last seen (UTC)"
    ]);
    for f in findings {
        table.add_row(row![
            f.rank,
            f.level,
            f.score,
            truncate(&f.title, 60),
            truncate(&attack(f), 40),
            f.count,
            hosts(f, 3),
            fmt_time(&f.first_seen),
            fmt_time(&f.last_seen)
        ]);
    }
    cs_print_table!(table);
}

/// Escapes text for a Markdown table cell, keeping it readable in its raw form.
pub fn md_escape(s: &str) -> String {
    s.replace('|', "\\|")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace(['\r', '\n'], " ")
}

/// Formats text as inline code for a Markdown table cell.
pub fn md_code(s: &str) -> String {
    if s.is_empty() {
        return String::new();
    }
    format!(
        "`{}`",
        s.replace('`', "'")
            .replace('|', "\\|")
            .replace(['\r', '\n'], " ")
    )
}

/// A Markdown report built from ranked findings plus any extra sections.
pub struct Report {
    pub title: String,
    pub meta: Vec<(String, String)>,
    pub findings: Vec<Finding>,
    pub sections: Vec<(String, String)>,
}

impl Report {
    pub fn to_markdown(&self) -> String {
        let mut md = format!("# {}\n\n", self.title);
        md.push_str("| | |\n| --- | --- |\n");
        md.push_str(&format!(
            "| Generated | {} |\n",
            Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
        ));
        for (k, v) in &self.meta {
            md.push_str(&format!("| {} | {} |\n", md_escape(k), md_escape(v)));
        }

        let hits: usize = self.findings.iter().map(|f| f.count).sum();
        let all_hosts: BTreeSet<&String> = self.findings.iter().flat_map(|f| &f.hosts).collect();
        md.push_str("\n## Summary\n\n");
        if self.findings.is_empty() {
            md.push_str("No findings.\n");
        } else {
            md.push_str(&format!(
                "{} from {} across {}.\n\n",
                plural(self.findings.len(), "finding"),
                plural(hits, "hit"),
                plural(all_hosts.len(), "host")
            ));
            md.push_str("| Severity | Findings | Hits |\n| --- | --- | --- |\n");
            for level in [
                Level::Critical,
                Level::High,
                Level::Medium,
                Level::Low,
                Level::Info,
            ] {
                let of_level: Vec<&Finding> =
                    self.findings.iter().filter(|f| f.level == level).collect();
                if !of_level.is_empty() {
                    md.push_str(&format!(
                        "| {} | {} | {} |\n",
                        capitalise(&level.to_string()),
                        of_level.len(),
                        of_level.iter().map(|f| f.count).sum::<usize>()
                    ));
                }
            }

            md.push_str("\n## Ranked findings\n\n");
            md.push_str("| # | Severity | Score | Finding | ATT&CK | Hits | Hosts | First seen (UTC) | Last seen (UTC) |\n");
            md.push_str("| --- | --- | --- | --- | --- | --- | --- | --- | --- |\n");
            for f in &self.findings {
                md.push_str(&format!(
                    "| {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
                    f.rank,
                    capitalise(&f.level.to_string()),
                    f.score,
                    md_escape(&f.title),
                    md_escape(&attack(f)),
                    f.count,
                    md_escape(&hosts(f, 3)),
                    fmt_time(&f.first_seen),
                    fmt_time(&f.last_seen)
                ));
            }

            md.push_str("\n## Details\n");
            for f in &self.findings {
                md.push_str(&format!("\n### {}. {}\n\n", f.rank, md_escape(&f.title)));
                md.push_str(&format!(
                    "- **Severity:** {} (score {})\n- **Category:** {} ({})\n",
                    capitalise(&f.level.to_string()),
                    f.score,
                    md_escape(&f.category),
                    md_escape(&f.source)
                ));
                if !f.tactics.is_empty() || !f.techniques.is_empty() {
                    md.push_str(&format!("- **ATT&CK:** {}\n", md_escape(&attack(f))));
                }
                md.push_str(&format!(
                    "- **Hits:** {} on {}\n- **Seen:** {} to {} UTC\n",
                    f.count,
                    if f.hosts.is_empty() {
                        "unknown hosts".to_string()
                    } else {
                        md_escape(&hosts(f, 10))
                    },
                    fmt_time(&f.first_seen),
                    fmt_time(&f.last_seen)
                ));
                if let Some(d) = &f.description {
                    md.push_str(&format!("- **Why it matters:** {}\n", md_escape(d)));
                }
                if !f.evidence.is_empty() {
                    md.push_str(
                        "\n| First seen (UTC) | Count | Host | Event | Detail |\n| --- | --- | --- | --- | --- |\n",
                    );
                    let mut evidence = f.evidence.clone();
                    evidence.sort_by_key(|e| e.timestamp);
                    // Collapse repeated identical evidence into one row.
                    let mut rows: Vec<(&Evidence, usize)> = vec![];
                    for e in &evidence {
                        match rows.iter_mut().find(|(r, _)| {
                            r.host == e.host && r.event == e.event && r.detail == e.detail
                        }) {
                            Some((_, n)) => *n += 1,
                            None => rows.push((e, 1)),
                        }
                    }
                    for (e, n) in rows {
                        md.push_str(&format!(
                            "| {} | {} | {} | {} | {} |\n",
                            fmt_time(&e.timestamp),
                            n,
                            md_escape(&e.host),
                            md_escape(&e.event),
                            md_code(&e.detail)
                        ));
                    }
                    if f.count > evidence.len() {
                        md.push_str(&format!(
                            "\n_Showing the first {} of {} hits._\n",
                            evidence.len(),
                            f.count
                        ));
                    }
                }
            }
        }
        for (title, body) in &self.sections {
            md.push_str(&format!("\n## {}\n\n{}\n", title, body.trim_end()));
        }
        md
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_attack_tags() {
        let tags = vec![
            "attack.persistence".to_string(),
            "attack.privilege-escalation".to_string(),
            "attack.t1543.003".to_string(),
            "car.2013-05-002".to_string(),
        ];
        let (tactics, techniques) = parse_tags(&tags);
        assert_eq!(tactics, vec!["persistence", "privilege_escalation"]);
        assert_eq!(techniques, vec!["T1543.003"]);
    }

    fn detection(name: &str, level: &str, tags: &[&str], host: &str, ts: &str) -> Json {
        json!({
            "name": name, "level": level, "source": "sigma", "group": "Sigma", "tags": tags,
            "timestamp": ts, "kind": "individual",
            "document": {"kind": "evtx", "data": {"Event": {
                "System": {"Computer": host, "EventID": 1, "Channel": "Sysmon"},
                "EventData": {"CommandLine": "evil.exe -x", "Image": "C:\\evil.exe"}
            }}}
        })
    }

    #[test]
    fn ranks_by_severity_then_impact() {
        let detections = vec![
            detection(
                "Discovery",
                "high",
                &["attack.discovery"],
                "A",
                "2024-01-01T00:00:00Z",
            ),
            detection(
                "Dump",
                "high",
                &["attack.credential-access"],
                "A",
                "2024-01-01T00:00:01Z",
            ),
            detection("Noise", "low", &[], "A", "2024-01-01T00:00:02Z"),
            detection(
                "Dump",
                "high",
                &["attack.credential-access"],
                "B",
                "2024-01-01T00:00:03Z",
            ),
            detection("Crit", "critical", &[], "A", "2024-01-01T00:00:04Z"),
        ];
        let findings = from_detections(&detections);
        let titles: Vec<&str> = findings.iter().map(|f| f.title.as_str()).collect();
        assert_eq!(titles, vec!["Dump", "Crit", "Discovery", "Noise"]);
        let dump = &findings[0];
        assert_eq!(dump.count, 2);
        assert_eq!(dump.hosts.len(), 2);
        assert_eq!(dump.score, 70 + 25 + 5);
        assert_eq!(
            dump.evidence[0].detail,
            "CommandLine: evil.exe -x; Image: C:\\evil.exe"
        );
    }

    #[test]
    fn renders_markdown() {
        let detections = vec![detection(
            "Pipe | Name",
            "medium",
            &["attack.execution"],
            "HOST",
            "2024-01-01T00:00:00Z",
        )];
        let report = Report {
            title: "Report".into(),
            meta: vec![("Evidence".into(), "C:\\logs".into())],
            findings: from_detections(&detections),
            sections: vec![("Notes".into(), "Extra".into())],
        };
        let md = report.to_markdown();
        assert!(md.contains("| 1 | Medium | 50 | Pipe \\| Name | execution | 1 | HOST |"));
        assert!(md.contains("### 1. Pipe \\| Name"));
        assert!(md.contains("## Notes\n\nExtra"));
    }
}
