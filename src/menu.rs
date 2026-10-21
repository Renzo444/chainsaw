//! Interactive terminal menu for Chainsaw.
//!
//! The menu is generated from Chainsaw's own clap definition, so every subcommand and option
//! the CLI supports is exposed automatically. Selected operations are validated with clap and
//! then executed by re-invoking the current executable, which keeps each run isolated (the
//! global writer and thread pool can only be initialised once per process).

use std::io::{self, BufRead, Write};
use std::path::{MAIN_SEPARATOR, Path, PathBuf};
use std::process::Command as Process;

use anyhow::Result;
use chainsaw::window::PRESETS;
use clap::{Arg, ArgAction, Command};
use ratatui::{
    DefaultTerminal, Frame,
    crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    layout::{Constraint, Layout, Rect},
    style::{Modifier, Style, Stylize},
    text::{Line, Span, Text},
    widgets::{Block, BorderType, Clear, List, ListItem, ListState, Paragraph, Wrap},
};

/// Subcommands that should not be offered from within the menu.
const HIDDEN: &[&str] = &["menu", "help"];

/// Choices for arguments whose types implement `FromStr` rather than `ValueEnum`, and so do not
/// advertise their possible values to clap.
fn known_choices(id: &str) -> Option<Vec<String>> {
    let choices: &[&str] = match id {
        "kind" => &["chainsaw", "sigma"],
        "level" | "min_level" => &["critical", "high", "medium", "low", "info"],
        "status" => &["stable", "experimental"],
        _ => return None,
    };
    Some(choices.iter().map(|s| s.to_string()).collect())
}

/// Presets for arguments that also accept a custom value.
fn preset_choices(id: &str) -> Option<Vec<String>> {
    match id {
        "last" => Some(PRESETS.iter().map(|s| s.to_string()).collect()),
        _ => None,
    }
}

#[derive(Clone, Debug, PartialEq)]
enum Kind {
    Flag,
    Count,
    Text {
        multiple: bool,
    },
    Choice {
        choices: Vec<String>,
        multiple: bool,
        /// Whether a value other than the choices may be typed in.
        custom: bool,
    },
}

#[derive(Clone, Debug)]
struct Field {
    label: String,
    help: String,
    heading: String,
    kind: Kind,
    /// The flag used on the command line, `None` for positional arguments.
    flag: Option<String>,
    required: bool,
    default: Option<String>,

    on: bool,
    count: u8,
    text: String,
    picked: Vec<bool>,
}

impl Field {
    fn from_arg(arg: &Arg, heading: &str) -> Option<Self> {
        let kind = match arg.get_action() {
            ArgAction::SetTrue => Kind::Flag,
            ArgAction::Count => Kind::Count,
            ArgAction::Set | ArgAction::Append => {
                let multiple = matches!(arg.get_action(), ArgAction::Append)
                    || arg
                        .get_num_args()
                        .map(|n| n.max_values() > 1)
                        .unwrap_or(false);
                let possible: Vec<String> = arg
                    .get_possible_values()
                    .iter()
                    .map(|v| v.get_name().to_string())
                    .collect();
                let id = arg.get_id().as_str();
                if let Some(choices) = preset_choices(id) {
                    Kind::Choice {
                        choices,
                        multiple,
                        custom: true,
                    }
                } else {
                    let choices = if possible.is_empty() {
                        known_choices(id)
                    } else {
                        Some(possible)
                    };
                    match choices {
                        Some(choices) => Kind::Choice {
                            choices,
                            multiple,
                            custom: false,
                        },
                        None => Kind::Text { multiple },
                    }
                }
            }
            // Help, version and anything else we do not know how to drive.
            _ => return None,
        };
        let flag = if arg.is_positional() {
            None
        } else if let Some(long) = arg.get_long() {
            Some(format!("--{}", long))
        } else {
            arg.get_short().map(|s| format!("-{}", s))
        };
        let label = match (&flag, arg.get_short(), arg.get_long()) {
            (None, _, _) => format!(
                "<{}>",
                arg.get_value_names()
                    .and_then(|v| v.first())
                    .map(|v| v.to_lowercase())
                    .unwrap_or_else(|| arg.get_id().to_string())
            ),
            (Some(_), Some(s), Some(l)) => format!("-{}, --{}", s, l),
            (Some(f), _, _) => f.clone(),
        };
        let help = arg
            .get_long_help()
            .or_else(|| arg.get_help())
            .map(|h| {
                h.to_string()
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_default();
        let default = arg
            .get_default_values()
            .first()
            .map(|v| v.to_string_lossy().to_string());
        let picked = match &kind {
            Kind::Choice { choices, .. } => vec![false; choices.len()],
            _ => vec![],
        };
        Some(Self {
            label,
            help,
            heading: arg
                .get_help_heading()
                .map(|h| h.to_string())
                .unwrap_or_else(|| heading.to_string()),
            kind,
            flag,
            required: arg.is_required_set(),
            default,
            on: false,
            count: 0,
            text: String::new(),
            picked,
        })
    }

    fn is_set(&self) -> bool {
        match self.kind {
            Kind::Flag => self.on,
            Kind::Count => self.count > 0,
            Kind::Text { .. } => !self.text.trim().is_empty(),
            Kind::Choice { .. } => !self.values().is_empty(),
        }
    }

    fn clear(&mut self) {
        self.on = false;
        self.count = 0;
        self.text.clear();
        self.picked.iter_mut().for_each(|p| *p = false);
    }

    /// The values this field contributes, before any flag is applied.
    fn values(&self) -> Vec<String> {
        match &self.kind {
            Kind::Text { multiple: true } => split_words(&self.text),
            Kind::Text { multiple: false } if self.text.trim().is_empty() => vec![],
            Kind::Text { multiple: false } => vec![self.text.trim().to_string()],
            Kind::Choice {
                choices, custom, ..
            } => {
                let picked: Vec<String> = choices
                    .iter()
                    .zip(&self.picked)
                    .filter(|(_, p)| **p)
                    .map(|(c, _)| c.clone())
                    .collect();
                if picked.is_empty() && *custom && !self.text.trim().is_empty() {
                    vec![self.text.trim().to_string()]
                } else {
                    picked
                }
            }
            _ => vec![],
        }
    }

    fn display_value(&self) -> String {
        match self.kind {
            Kind::Flag => if self.on { "[x]" } else { "[ ]" }.to_string(),
            Kind::Count => format!("{}", self.count),
            Kind::Text { .. } => self.text.clone(),
            Kind::Choice { .. } => self.values().join(", "),
        }
    }

    fn hint(&self) -> String {
        let mut hints = vec![];
        match &self.kind {
            Kind::Flag => hints.push("Enter/Space toggles".to_string()),
            Kind::Count => hints.push("←/→ adjusts".to_string()),
            Kind::Text { multiple: true } => {
                hints.push("multiple values, space separated (quote values with spaces)".into())
            }
            Kind::Choice {
                choices,
                multiple,
                custom,
            } => hints.push(format!(
                "{}: {}{}",
                if *multiple { "pick any" } else { "pick one" },
                choices.join(", "),
                if *custom { ", or a custom value" } else { "" }
            )),
            _ => {}
        }
        if let Some(default) = &self.default {
            hints.push(format!("default: {}", default));
        }
        if self.required {
            hints.push("required".into());
        }
        hints.join(" · ")
    }
}

#[derive(Clone, Debug)]
struct Operation {
    path: Vec<String>,
    about: String,
    fields: Vec<Field>,
}

impl Operation {
    fn name(&self) -> String {
        self.path.join(" ")
    }

    /// Builds the arguments (excluding the program name) for this operation.
    fn argv(&self) -> Vec<String> {
        let mut globals = vec![];
        let mut options = vec![];
        let mut positionals = vec![];
        for field in &self.fields {
            let target = if field.heading == GLOBAL_HEADING {
                &mut globals
            } else {
                &mut options
            };
            match (&field.flag, &field.kind) {
                (Some(flag), Kind::Flag) if field.on => target.push(flag.clone()),
                (Some(flag), Kind::Count) => {
                    (0..field.count).for_each(|_| target.push(flag.clone()))
                }
                (Some(flag), _) => {
                    for value in field.values() {
                        target.push(flag.clone());
                        target.push(value);
                    }
                }
                (None, _) => positionals.extend(field.values()),
            }
        }
        let mut argv = globals;
        argv.extend(self.path.iter().cloned());
        argv.extend(options);
        if positionals.iter().any(|p| p.starts_with('-')) {
            argv.push("--".into());
        }
        argv.extend(positionals);
        argv
    }

    fn preview(&self) -> String {
        std::iter::once("rockwheel".to_string())
            .chain(self.argv().iter().map(|a| quote(a)))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

const GLOBAL_HEADING: &str = "Global Options";

fn operations(root: &Command) -> Vec<Operation> {
    let globals: Vec<Field> = root
        .get_arguments()
        .filter_map(|a| Field::from_arg(a, GLOBAL_HEADING))
        .collect();
    let mut ops = vec![];
    fn walk(cmd: &Command, path: Vec<String>, globals: &[Field], ops: &mut Vec<Operation>) {
        for sub in cmd.get_subcommands() {
            if HIDDEN.contains(&sub.get_name()) {
                continue;
            }
            let mut path = path.clone();
            path.push(sub.get_name().to_string());
            if sub.has_subcommands() {
                walk(sub, path, globals, ops);
                continue;
            }
            let mut fields: Vec<Field> = sub
                .get_positionals()
                .filter_map(|a| Field::from_arg(a, "Arguments"))
                .collect();
            fields.extend(
                sub.get_arguments()
                    .filter(|a| !a.is_positional())
                    .filter_map(|a| Field::from_arg(a, "Options")),
            );
            fields.extend(globals.iter().cloned());
            ops.push(Operation {
                path,
                about: sub.get_about().map(|a| a.to_string()).unwrap_or_default(),
                fields,
            });
        }
    }
    walk(root, vec![], &globals, &mut ops);
    // List operations in the order an investigation usually runs; anything new goes last.
    ops.sort_by_key(|op| {
        ORDER
            .iter()
            .position(|o| *o == op.name())
            .unwrap_or(ORDER.len())
    });
    ops
}

/// The order operations are listed in the menu.
const ORDER: &[&str] = &[
    "hunt",
    "persistence",
    "ioc",
    "process",
    "search",
    "analyse evtx",
    "analyse gaps",
    "analyse shimcache",
    "analyse srum",
    "dump",
    "lint",
];

/// Greedy word wrap to `width` columns. Words longer than a line are left whole.
fn wrap_words(text: &str, width: usize) -> Vec<String> {
    let mut lines = vec![String::new()];
    for word in text.split_whitespace() {
        let line = lines.last_mut().expect("never empty");
        if line.is_empty() {
            line.push_str(word);
        } else if line.chars().count() + 1 + word.chars().count() <= width {
            line.push(' ');
            line.push_str(word);
        } else {
            lines.push(word.to_string());
        }
    }
    lines
}

/// Splits a string into words on whitespace, honouring single and double quotes. Backslashes
/// are not treated as escapes so that Windows paths can be entered as-is.
fn split_words(s: &str) -> Vec<String> {
    let mut words = vec![];
    let mut word = String::new();
    let mut in_word = false;
    let mut quote: Option<char> = None;
    for c in s.chars() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => word.push(c),
            None if c == '"' || c == '\'' => {
                quote = Some(c);
                in_word = true;
            }
            None if c.is_whitespace() => {
                if in_word {
                    words.push(std::mem::take(&mut word));
                    in_word = false;
                }
            }
            None => {
                word.push(c);
                in_word = true;
            }
        }
    }
    if in_word {
        words.push(word);
    }
    words
}

fn quote(s: &str) -> String {
    if !s.is_empty()
        && !s
            .chars()
            .any(|c| c.is_whitespace() || "'\"$`;&|<>*?".contains(c))
    {
        s.to_string()
    } else if !s.contains('\'') {
        format!("'{}'", s)
    } else {
        format!("\"{}\"", s.replace('"', "\\\""))
    }
}

/// Completes the last path in `input` against the filesystem. Returns the new input and the
/// candidates that matched.
fn complete_path(input: &str, multiple: bool) -> (String, Vec<String>) {
    let start = if multiple {
        input.rfind(char::is_whitespace).map(|i| i + 1).unwrap_or(0)
    } else {
        0
    };
    let (head, token) = input.split_at(start);
    let token = token.trim_start_matches(['"', '\'']);
    let sep = token.rfind(['/', '\\']).map(|i| i + 1).unwrap_or(0);
    let (dir, prefix) = token.split_at(sep);
    let read = if dir.is_empty() { "." } else { dir };
    let Ok(entries) = std::fs::read_dir(read) else {
        return (input.to_string(), vec![]);
    };
    let lower = prefix.to_lowercase();
    let mut matches: Vec<(String, bool)> = entries
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            (name.to_lowercase().starts_with(&lower)
                && (prefix.starts_with('.') || !name.starts_with('.')))
            .then(|| (name, e.path().is_dir()))
        })
        .collect();
    matches.sort();
    let completed = match matches.as_slice() {
        [] => return (input.to_string(), vec![]),
        [(name, is_dir)] => {
            let mut c = format!("{}{}", dir, name);
            if *is_dir {
                c.push(MAIN_SEPARATOR);
            }
            c
        }
        many => {
            let first = &many[0].0;
            let mut len = first.len();
            for (name, _) in &many[1..] {
                len = first
                    .chars()
                    .zip(name.chars())
                    .take_while(|(a, b)| a.eq_ignore_ascii_case(b))
                    .map(|(a, _)| a.len_utf8())
                    .sum::<usize>()
                    .min(len);
            }
            format!(
                "{}{}",
                dir,
                &first[..len.max(prefix.len()).min(first.len())]
            )
        }
    };
    let completed = if completed.contains(char::is_whitespace) && multiple {
        format!("\"{}", completed)
    } else {
        completed
    };
    let names = matches
        .into_iter()
        .map(|(n, d)| {
            if d {
                format!("{}{}", n, MAIN_SEPARATOR)
            } else {
                n
            }
        })
        .collect();
    (format!("{}{}", head, completed), names)
}

enum Screen {
    Main,
    Form,
}

enum Popup {
    None,
    Message {
        title: String,
        body: String,
        scroll: u16,
    },
    Picker {
        state: ListState,
    },
}

struct Editor {
    text: String,
    cursor: usize,
}

struct App {
    root: Command,
    exe: PathBuf,
    ops: Vec<Operation>,
    screen: Screen,
    main: ListState,
    op: usize,
    form: ListState,
    editor: Option<Editor>,
    popup: Popup,
    status: Option<String>,
}

enum Action {
    None,
    Run,
    Quit,
}

impl App {
    fn new(root: Command) -> Result<Self> {
        let ops = operations(&root);
        Ok(Self {
            root,
            exe: std::env::current_exe()?,
            ops,
            screen: Screen::Main,
            main: ListState::default().with_selected(Some(0)),
            op: 0,
            form: ListState::default().with_selected(Some(0)),
            editor: None,
            popup: Popup::None,
            status: None,
        })
    }

    fn op(&self) -> &Operation {
        &self.ops[self.op]
    }

    /// The selected form row; one past the last field is the run button.
    fn row(&self) -> usize {
        self.form.selected().unwrap_or(0)
    }

    fn field_mut(&mut self) -> Option<&mut Field> {
        let row = self.row();
        self.ops[self.op].fields.get_mut(row)
    }

    fn validate(&self) -> std::result::Result<(), String> {
        let mut argv = vec!["rockwheel".to_string()];
        argv.extend(self.op().argv());
        self.root
            .clone()
            .try_get_matches_from(argv)
            .map(|_| ())
            .map_err(|e| e.render().to_string())
    }

    fn handle(&mut self, key: KeyEvent) -> Action {
        if key.kind != KeyEventKind::Press {
            return Action::None;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return Action::Quit;
        }
        self.status = None;
        match self.popup {
            Popup::Message { ref mut scroll, .. } => {
                match key.code {
                    KeyCode::Up | KeyCode::Char('k') => *scroll = scroll.saturating_sub(1),
                    KeyCode::Down | KeyCode::Char('j') => *scroll = scroll.saturating_add(1),
                    KeyCode::PageUp => *scroll = scroll.saturating_sub(10),
                    KeyCode::PageDown => *scroll = scroll.saturating_add(10),
                    _ => self.popup = Popup::None,
                }
                return Action::None;
            }
            Popup::Picker { .. } => {
                self.handle_picker(key);
                return Action::None;
            }
            Popup::None => {}
        }
        if self.editor.is_some() {
            self.handle_editor(key);
            return Action::None;
        }
        match self.screen {
            Screen::Main => self.handle_main(key),
            Screen::Form => self.handle_form(key),
        }
    }

    fn handle_main(&mut self, key: KeyEvent) -> Action {
        let len = self.ops.len() + 1;
        let i = self.main.selected().unwrap_or(0);
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.main.select(Some((i + len - 1) % len)),
            KeyCode::Down | KeyCode::Char('j') => self.main.select(Some((i + 1) % len)),
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                if i == self.ops.len() {
                    return Action::Quit;
                }
                self.op = i;
                self.form.select(Some(0));
                self.screen = Screen::Form;
            }
            KeyCode::Char('q') => return Action::Quit,
            _ => {}
        }
        Action::None
    }

    fn handle_form(&mut self, key: KeyEvent) -> Action {
        let len = self.op().fields.len() + 1;
        let row = self.row();
        let run = key.code == KeyCode::F(5)
            || (key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('r'));
        if run || (row == len - 1 && matches!(key.code, KeyCode::Enter | KeyCode::Char(' '))) {
            return match self.validate() {
                Ok(()) => Action::Run,
                Err(body) => {
                    self.popup = Popup::Message {
                        title: "Cannot run yet".into(),
                        body,
                        scroll: 0,
                    };
                    Action::None
                }
            };
        }
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.form.select(Some((row + len - 1) % len)),
            KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => {
                self.form.select(Some((row + 1) % len))
            }
            KeyCode::BackTab => self.form.select(Some((row + len - 1) % len)),
            KeyCode::Home | KeyCode::Char('g') => self.form.select(Some(0)),
            KeyCode::End | KeyCode::Char('G') => self.form.select(Some(len - 1)),
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Left if !self.is_count_row() => {
                self.screen = Screen::Main;
            }
            KeyCode::Char('?') => {
                let mut help = self.root.clone();
                let mut cmd = &mut help;
                for p in &self.ops[self.op].path {
                    cmd = cmd.find_subcommand_mut(p).expect("subcommand exists");
                }
                self.popup = Popup::Message {
                    title: format!("rockwheel {} --help", self.op().name()),
                    body: cmd.render_long_help().to_string(),
                    scroll: 0,
                };
            }
            KeyCode::Char('x') | KeyCode::Delete | KeyCode::Backspace => {
                if let Some(f) = self.field_mut() {
                    f.clear();
                }
            }
            KeyCode::Char('X') => self.ops[self.op].fields.iter_mut().for_each(Field::clear),
            KeyCode::Left | KeyCode::Char('-') => {
                if let Some(f) = self.field_mut()
                    && f.kind == Kind::Count
                {
                    f.count = f.count.saturating_sub(1);
                }
            }
            KeyCode::Right | KeyCode::Char('+') => {
                if let Some(f) = self.field_mut()
                    && f.kind == Kind::Count
                {
                    f.count = (f.count + 1).min(5);
                }
            }
            KeyCode::Enter | KeyCode::Char(' ') | KeyCode::Char('e') => {
                let Some(f) = self.field_mut() else {
                    return Action::None;
                };
                match f.kind {
                    Kind::Flag => f.on = !f.on,
                    Kind::Count => f.count = (f.count + 1) % 6,
                    Kind::Text { .. } => {
                        self.editor = Some(Editor {
                            cursor: f.text.len(),
                            text: f.text.clone(),
                        })
                    }
                    Kind::Choice { .. } => {
                        self.popup = Popup::Picker {
                            state: ListState::default().with_selected(Some(0)),
                        }
                    }
                }
            }
            _ => {}
        }
        Action::None
    }

    fn is_count_row(&self) -> bool {
        self.op()
            .fields
            .get(self.row())
            .map(|f| f.kind == Kind::Count)
            .unwrap_or(false)
    }

    fn handle_picker(&mut self, key: KeyEvent) {
        let Popup::Picker { state } = &mut self.popup else {
            return;
        };
        let i = state.selected().unwrap_or(0);
        let row = self.form.selected().unwrap_or(0);
        let field = &mut self.ops[self.op].fields[row];
        let Kind::Choice {
            choices,
            multiple,
            custom,
        } = &field.kind
        else {
            return;
        };
        let len = choices.len() + usize::from(*custom);
        if *custom && i == choices.len() && matches!(key.code, KeyCode::Enter | KeyCode::Char(' '))
        {
            self.editor = Some(Editor {
                cursor: field.text.len(),
                text: field.text.clone(),
            });
            self.popup = Popup::None;
            return;
        }
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => state.select(Some((i + len - 1) % len)),
            KeyCode::Down | KeyCode::Char('j') => state.select(Some((i + 1) % len)),
            KeyCode::Char(' ') if *multiple => field.picked[i] = !field.picked[i],
            KeyCode::Char(' ') | KeyCode::Enter if !*multiple => {
                let was = field.picked[i];
                field.picked.iter_mut().for_each(|p| *p = false);
                field.picked[i] = !was;
                field.text.clear();
                self.popup = Popup::None;
            }
            KeyCode::Enter | KeyCode::Esc => self.popup = Popup::None,
            _ => {}
        }
    }

    fn handle_editor(&mut self, key: KeyEvent) {
        let row = self.row();
        let multiple = matches!(self.op().fields[row].kind, Kind::Text { multiple: true });
        let Some(editor) = self.editor.as_mut() else {
            return;
        };
        match key.code {
            KeyCode::Esc => self.editor = None,
            KeyCode::Enter => {
                let text = editor.text.clone();
                let field = &mut self.ops[self.op].fields[row];
                field.text = text;
                // A custom value replaces any picked choice.
                field.picked.iter_mut().for_each(|p| *p = false);
                self.editor = None;
            }
            KeyCode::Tab => {
                let (head, tail) = editor.text.split_at(editor.cursor);
                let (completed, candidates) = complete_path(head, multiple);
                editor.text = format!("{}{}", completed, tail);
                editor.cursor = completed.len();
                if candidates.len() > 1 {
                    self.status = Some(candidates.join("  "));
                } else if candidates.is_empty() {
                    self.status = Some("No matching paths".into());
                }
            }
            KeyCode::Left => {
                editor.cursor = editor.text[..editor.cursor]
                    .char_indices()
                    .last()
                    .map(|(i, _)| i)
                    .unwrap_or(0)
            }
            KeyCode::Right => {
                editor.cursor = editor.text[editor.cursor..]
                    .char_indices()
                    .nth(1)
                    .map(|(i, _)| editor.cursor + i)
                    .unwrap_or(editor.text.len())
            }
            KeyCode::Home => editor.cursor = 0,
            KeyCode::End => editor.cursor = editor.text.len(),
            KeyCode::Backspace => {
                if let Some((i, _)) = editor.text[..editor.cursor].char_indices().last() {
                    editor.text.remove(i);
                    editor.cursor = i;
                }
            }
            KeyCode::Delete => {
                if editor.cursor < editor.text.len() {
                    editor.text.remove(editor.cursor);
                }
            }
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                editor.text.drain(..editor.cursor);
                editor.cursor = 0;
            }
            KeyCode::Char(c) => {
                editor.text.insert(editor.cursor, c);
                editor.cursor += c.len_utf8();
            }
            _ => {}
        }
    }

    fn draw(&mut self, frame: &mut Frame) {
        // The full block-letter banner only on the main screen, and only when it leaves room.
        let area = frame.area();
        let art = matches!(self.screen, Screen::Main)
            && area.height >= 32
            && area.width as usize >= crate::banner::width(crate::banner::WORD) + 2;
        let banner_height = if art {
            crate::banner::WORD.lines().count() as u16 + 1
        } else {
            0
        };
        let [banner, header, body, footer] = Layout::vertical([
            Constraint::Length(banner_height),
            Constraint::Length(1),
            Constraint::Min(5),
            Constraint::Length(1),
        ])
        .areas(area);
        if art {
            let lines: Vec<Line> = crate::banner::WORD
                .lines()
                .map(|l| Line::from(format!(" {}", l)).green().bold())
                .collect();
            frame.render_widget(Text::from(lines), banner);
        }
        frame.render_widget(
            Line::from(vec![
                Span::styled(" ROCKWHEEL ", Style::new().black().on_green().bold()),
                Span::raw(format!(
                    " {} · interactive menu · built on Chainsaw",
                    env!("CARGO_PKG_VERSION")
                )),
            ]),
            header,
        );
        match self.screen {
            Screen::Main => self.draw_main(frame, body),
            Screen::Form => self.draw_form(frame, body),
        }
        let keys = if let Some(status) = &self.status {
            Line::from(status.clone()).yellow()
        } else if self.editor.is_some() {
            Line::from(" Enter save · Esc cancel · Tab complete path · Ctrl+U clear").dark_gray()
        } else {
            match (&self.popup, &self.screen) {
                (Popup::Picker { .. }, _) => {
                    Line::from(" ↑↓ move · Space toggle · Enter done").dark_gray()
                }
                (Popup::Message { .. }, _) => Line::from(" ↑↓ PgUp PgDn scroll · any other key closes").dark_gray(),
                (_, Screen::Main) => Line::from(" ↑↓ move · Enter open · q quit").dark_gray(),
                (_, Screen::Form) => Line::from(
                    " ↑↓ move · Enter edit/toggle · x clear · X clear all · ? help · F5/Ctrl+R run · Esc back",
                )
                .dark_gray(),
            }
        };
        frame.render_widget(keys, footer);
        self.draw_popup(frame);
    }

    fn draw_main(&mut self, frame: &mut Frame, area: Rect) {
        let [left, right] =
            Layout::horizontal([Constraint::Length(28), Constraint::Min(20)]).areas(area);
        let mut items: Vec<ListItem> = self
            .ops
            .iter()
            .map(|op| ListItem::new(format!(" {}", op.name())))
            .collect();
        items.push(ListItem::new(" quit").dark_gray());
        let list = List::new(items)
            .block(
                Block::bordered()
                    .border_type(BorderType::Rounded)
                    .title(" Operations "),
            )
            .highlight_style(Style::new().black().on_green())
            .highlight_symbol("▶");
        frame.render_stateful_widget(list, left, &mut self.main);

        let i = self.main.selected().unwrap_or(0);
        let text = match self.ops.get(i) {
            Some(op) => {
                let mut lines = vec![
                    Line::from(format!("rockwheel {}", op.name()))
                        .bold()
                        .green(),
                    Line::from(op.about.clone()),
                ];
                let mut heading = "";
                for f in &op.fields {
                    if f.heading != heading {
                        heading = &f.heading;
                        lines.push(Line::from(""));
                        lines.push(Line::from(heading.to_string()).underlined());
                    }
                    // Wrap the help ourselves so continuation lines stay under the description.
                    let room = (right.width as usize).saturating_sub(2 + 30).max(20);
                    for (n, chunk) in wrap_words(&f.help, room).into_iter().enumerate() {
                        let label = if n == 0 { f.label.as_str() } else { "" };
                        lines.push(Line::from(vec![
                            Span::styled(format!("  {:<28}", label), Style::new().cyan()),
                            Span::raw(chunk),
                        ]));
                    }
                }
                Text::from(lines)
            }
            None => Text::from("Exit the menu."),
        };
        frame.render_widget(
            Paragraph::new(text).wrap(Wrap { trim: false }).block(
                Block::bordered()
                    .border_type(BorderType::Rounded)
                    .title(" Details "),
            ),
            right,
        );
    }

    fn draw_form(&mut self, frame: &mut Frame, area: Rect) {
        let preview = self.op().preview();
        let width = area.width.saturating_sub(4).max(1) as usize;
        let preview_height = (preview.chars().count() / width + 1).min(6) as u16 + 2;
        let [list_area, help_area, preview_area] = Layout::vertical([
            Constraint::Min(3),
            Constraint::Length(5),
            Constraint::Length(preview_height),
        ])
        .areas(area);

        let op = &self.ops[self.op];
        let label_width = op.fields.iter().map(|f| f.label.len()).max().unwrap_or(10) + 2;
        let mut items = vec![];
        let mut heading = "";
        let mut item_index = vec![];
        for (i, f) in op.fields.iter().enumerate() {
            if f.heading != heading {
                heading = &f.heading;
                items.push(ListItem::new(
                    Line::from(format!(" {}", heading)).bold().underlined(),
                ));
            }
            item_index.push(items.len());
            let marker = if f.required { "*" } else { " " };
            let editing = self.editor.is_some() && self.row() == i;
            let value = if editing {
                let e = self.editor.as_ref().expect("editor present");
                let (a, b) = e.text.split_at(e.cursor);
                let mut chars = b.chars();
                let at = chars.next().map(String::from).unwrap_or(" ".into());
                Line::from(vec![
                    Span::raw(a.to_string()),
                    Span::styled(at, Style::new().add_modifier(Modifier::REVERSED)),
                    Span::raw(chars.collect::<String>()),
                ])
            } else if !f.is_set() && !matches!(f.kind, Kind::Flag | Kind::Count) {
                Line::from(
                    f.default
                        .as_ref()
                        .map(|d| format!("({})", d))
                        .unwrap_or_default(),
                )
                .dark_gray()
            } else {
                Line::from(f.display_value()).yellow()
            };
            let mut spans = vec![
                Span::styled(marker, Style::new().red()),
                Span::styled(
                    format!("{:<width$}", f.label, width = label_width),
                    if f.is_set() {
                        Style::new().cyan().bold()
                    } else {
                        Style::new().cyan()
                    },
                ),
            ];
            spans.extend(value.spans.into_iter().map(|s| s.patch_style(value.style)));
            items.push(ListItem::new(Line::from(spans)));
        }
        item_index.push(items.len() + 1);
        items.push(ListItem::new(""));
        items.push(ListItem::new(Line::from(" ▶ Run").green().bold()));

        let mut state = ListState::default().with_selected(Some(item_index[self.row()]));
        // Keep the previous scroll position where possible.
        *state.offset_mut() = self.form.offset();
        let list = List::new(items)
            .block(
                Block::bordered()
                    .border_type(BorderType::Rounded)
                    .title(format!(" rockwheel {} ", op.name()))
                    .title_bottom(Line::from(format!(" {} ", op.about)).dark_gray()),
            )
            .highlight_style(Style::new().add_modifier(Modifier::REVERSED))
            .highlight_symbol("▶");
        frame.render_stateful_widget(list, list_area, &mut state);
        *self.form.offset_mut() = state.offset();

        let help = match op.fields.get(self.row()) {
            Some(f) => Text::from(vec![
                Line::from(f.help.clone()),
                Line::from(f.hint()).dark_gray(),
            ]),
            None => Text::from("Validate and run the command shown below."),
        };
        frame.render_widget(
            Paragraph::new(help).wrap(Wrap { trim: true }).block(
                Block::bordered()
                    .border_type(BorderType::Rounded)
                    .title(" Help "),
            ),
            help_area,
        );
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::raw("$ ").dark_gray(),
                Span::raw(preview).green(),
            ]))
            .wrap(Wrap { trim: false })
            .block(
                Block::bordered()
                    .border_type(BorderType::Rounded)
                    .title(" Command "),
            ),
            preview_area,
        );
    }

    fn draw_popup(&mut self, frame: &mut Frame) {
        let area = frame.area();
        match &mut self.popup {
            Popup::None => {}
            Popup::Message {
                title,
                body,
                scroll,
            } => {
                let lines = body.lines().count() as u16 + 2;
                let height = lines.min(area.height.saturating_sub(4));
                *scroll = (*scroll).min(lines.saturating_sub(height));
                let popup = centered(area, area.width.saturating_sub(8).min(100), height);
                frame.render_widget(Clear, popup);
                frame.render_widget(
                    Paragraph::new(body.trim_end().to_string())
                        .wrap(Wrap { trim: false })
                        .scroll((*scroll, 0))
                        .block(
                            Block::bordered()
                                .border_type(BorderType::Rounded)
                                .title(format!(" {} ", title))
                                .border_style(Style::new().yellow()),
                        ),
                    popup,
                );
            }
            Popup::Picker { state } => {
                let row = self.form.selected().unwrap_or(0);
                let field = &self.ops[self.op].fields[row];
                let Kind::Choice {
                    choices,
                    multiple,
                    custom,
                } = &field.kind
                else {
                    return;
                };
                let mut items: Vec<ListItem> = choices
                    .iter()
                    .zip(&field.picked)
                    .map(|(c, p)| {
                        let mark = match (multiple, p) {
                            (true, true) => "[x]",
                            (true, false) => "[ ]",
                            (false, true) => "(•)",
                            (false, false) => "( )",
                        };
                        ListItem::new(format!(" {} {}", mark, c))
                    })
                    .collect();
                if *custom {
                    let current = if field.picked.iter().any(|p| *p) {
                        String::new()
                    } else {
                        field.text.clone()
                    };
                    items.push(ListItem::new(format!(
                        " ✎  Custom… {}",
                        if current.is_empty() {
                            String::new()
                        } else {
                            format!("({})", current)
                        }
                    )));
                }
                let popup = centered(area, 40, items.len() as u16 + 2);
                frame.render_widget(Clear, popup);
                frame.render_stateful_widget(
                    List::new(items)
                        .block(
                            Block::bordered()
                                .border_type(BorderType::Rounded)
                                .title(format!(" {} ", field.label)),
                        )
                        .highlight_style(Style::new().black().on_green()),
                    popup,
                    state,
                );
            }
        }
    }
}

fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    Rect {
        x: area.x + (area.width - width) / 2,
        y: area.y + (area.height - height) / 2,
        width,
        height,
    }
}

/// Runs the selected operation as a child process with the terminal restored to normal mode.
fn execute(exe: &Path, op: &Operation) -> Result<()> {
    let mut stdout = io::stdout();
    writeln!(stdout, "\n$ {}\n", op.preview())?;
    stdout.flush()?;
    match Process::new(exe).args(op.argv()).status() {
        Ok(status) if status.success() => writeln!(stdout, "\n[+] Finished successfully")?,
        Ok(status) => match status.code() {
            Some(code) => writeln!(stdout, "\n[x] Exited with status {}", code)?,
            None => writeln!(stdout, "\n[x] Interrupted")?,
        },
        Err(e) => writeln!(stdout, "\n[x] Failed to start rockwheel - {}", e)?,
    }
    write!(stdout, "Press Enter to return to the menu...")?;
    stdout.flush()?;
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    Ok(())
}

fn event_loop(app: &mut App, terminal: &mut DefaultTerminal) -> Result<Option<usize>> {
    loop {
        terminal.draw(|f| app.draw(f))?;
        if let Event::Key(key) = event::read()? {
            match app.handle(key) {
                Action::None => {}
                Action::Run => return Ok(Some(app.op)),
                Action::Quit => return Ok(None),
            }
        }
    }
}

/// Launches the interactive menu for the provided clap command tree.
pub fn run(root: Command) -> Result<()> {
    // Ctrl+C should stop the running operation, not the menu itself.
    let _ = ctrlc::set_handler(|| {});
    let mut app = App::new(root)?;
    loop {
        let mut terminal = ratatui::init();
        let result = event_loop(&mut app, &mut terminal);
        ratatui::restore();
        match result? {
            Some(op) => execute(&app.exe, &app.ops[op])?,
            None => return Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Root {
        #[arg(long)]
        no_banner: bool,
        #[arg(short = 'v', action = ArgAction::Count)]
        verbose: u8,
        #[command(subcommand)]
        cmd: Sub,
    }

    #[derive(clap::Subcommand)]
    enum Sub {
        Hunt {
            rules: Option<PathBuf>,
            path: Vec<PathBuf>,
            #[arg(short = 'm', long = "mapping", number_of_values = 1)]
            mapping: Option<Vec<PathBuf>>,
            #[arg(long = "level", number_of_values = 1)]
            level: Vec<String>,
            #[arg(short = 'j', long = "json")]
            json: bool,
            #[arg(short = 'q')]
            quiet: bool,
        },
        Analyse {
            #[command(subcommand)]
            cmd: AnalyseSub,
        },
        Menu,
    }

    #[derive(clap::Subcommand)]
    enum AnalyseSub {
        Gaps {
            path: Vec<PathBuf>,
            #[arg(long, default_value_t = 30)]
            minutes: i64,
        },
    }

    fn ops() -> Vec<Operation> {
        use clap::CommandFactory;
        operations(&Root::command())
    }

    #[test]
    fn wraps_words_to_width() {
        assert_eq!(
            wrap_words("one two three four", 9),
            vec!["one two", "three", "four"]
        );
        assert_eq!(wrap_words("", 9), vec![""]);
    }

    #[test]
    fn lists_nested_operations_and_hides_menu() {
        let names: Vec<String> = ops().iter().map(|o| o.name()).collect();
        assert_eq!(names, vec!["hunt", "analyse gaps"]);
        assert!(ORDER.contains(&"persistence"));
    }

    #[test]
    fn classifies_fields() {
        let hunt = &ops()[0];
        let kind = |label: &str| {
            hunt.fields
                .iter()
                .find(|f| f.label == label)
                .unwrap_or_else(|| panic!("missing {}", label))
                .kind
                .clone()
        };
        assert_eq!(kind("<rules>"), Kind::Text { multiple: false });
        assert_eq!(kind("<path>"), Kind::Text { multiple: true });
        assert_eq!(kind("-m, --mapping"), Kind::Text { multiple: true });
        assert_eq!(kind("-j, --json"), Kind::Flag);
        assert_eq!(kind("-q"), Kind::Flag);
        assert_eq!(kind("-v"), Kind::Count);
        assert!(matches!(
            kind("--level"),
            Kind::Choice { multiple: true, .. }
        ));
    }

    #[test]
    fn builds_argv() {
        let mut hunt = ops()[0].clone();
        for f in hunt.fields.iter_mut() {
            match f.label.as_str() {
                "<rules>" => f.text = "rules/".into(),
                "<path>" => f.text = r#"logs/a.evtx "C:\Some Dir\b.evtx""#.into(),
                "-m, --mapping" => f.text = "m1.yml m2.yml".into(),
                "--level" => {
                    f.picked[0] = true;
                    f.picked[1] = true;
                }
                "-q" => f.on = true,
                "-v" => f.count = 2,
                "--no-banner" => f.on = true,
                _ => {}
            }
        }
        let argv = hunt.argv();
        assert_eq!(
            argv,
            vec![
                "--no-banner",
                "-v",
                "-v",
                "hunt",
                "--mapping",
                "m1.yml",
                "--mapping",
                "m2.yml",
                "--level",
                "critical",
                "--level",
                "high",
                "-q",
                "rules/",
                "logs/a.evtx",
                r"C:\Some Dir\b.evtx",
            ]
        );
        use clap::CommandFactory;
        let mut full = vec!["rockwheel".to_string()];
        full.extend(argv);
        assert!(Root::command().try_get_matches_from(full).is_ok());
        assert!(
            hunt.preview()
                .ends_with(r"logs/a.evtx 'C:\Some Dir\b.evtx'")
        );
    }

    #[test]
    fn nested_argv_and_dash_positionals() {
        let mut gaps = ops()[1].clone();
        gaps.fields[0].text = "-weird.evtx".into();
        assert_eq!(gaps.argv(), vec!["analyse", "gaps", "--", "-weird.evtx"]);
        assert_eq!(
            gaps.fields
                .iter()
                .find(|f| f.label == "--minutes")
                .unwrap()
                .default,
            Some("30".into())
        );
    }

    #[test]
    fn splits_words() {
        assert_eq!(split_words(""), Vec::<String>::new());
        assert_eq!(split_words(" a  b "), vec!["a", "b"]);
        assert_eq!(
            split_words(r#"'a b' "c d" e\f"#),
            vec!["a b", "c d", r"e\f"]
        );
        assert_eq!(split_words(r#""""#), vec![""]);
    }

    #[test]
    fn completes_paths() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("rules")).unwrap();
        std::fs::write(dir.path().join("sample_one.evtx"), "").unwrap();
        std::fs::write(dir.path().join("sample_two.evtx"), "").unwrap();
        let base = format!("{}{}", dir.path().display(), MAIN_SEPARATOR);

        let (out, _) = complete_path(&format!("{}ru", base), false);
        assert_eq!(out, format!("{}rules{}", base, MAIN_SEPARATOR));

        let (out, candidates) = complete_path(&format!("x {}sa", base), true);
        assert_eq!(out, format!("x {}sample_", base));
        assert_eq!(candidates.len(), 2);
    }
}
