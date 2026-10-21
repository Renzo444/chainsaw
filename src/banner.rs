//! The Rockwheel banner: a block-letter title and, on wide terminals, the saw itself.

/// The block-letter "ROCKWHEEL" title.
pub const WORD: &str = include_str!("art/word.txt");

/// A big ASCII chainsaw, about 130 columns wide.
pub const SAW: &str = include_str!("art/saw.txt");

const CREDIT: &str = "Built on Chainsaw by WithSecure Countercept (@FranticTyping, @AlexKornitzer)";

/// The widest line in a piece of art, in terminal columns.
pub fn width(art: &str) -> usize {
    art.lines().map(|l| l.chars().count()).max().unwrap_or(0)
}

/// The banner to print at a terminal `columns` wide. The saw is left out when it would wrap.
pub fn title(columns: usize) -> String {
    let mut out = String::new();
    if columns >= width(SAW) {
        out.push_str(SAW);
        out.push('\n');
    }
    out.push_str(WORD);
    out.push_str(&format!("    {} · {}\n", env!("CARGO_PKG_VERSION"), CREDIT));
    out
}

/// The width of the terminal on stderr, or 80 when it is not a terminal.
pub fn terminal_width() -> usize {
    use terminal_size::{Width, terminal_size_of};
    terminal_size_of(std::io::stderr())
        .map(|(Width(w), _)| w as usize)
        .unwrap_or(80)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saw_only_when_it_fits() {
        assert!(title(width(SAW)).contains("(@)"));
        assert!(!title(width(SAW) - 1).contains("(@)"));
        assert!(title(80).contains("╚══════╝"));
    }
}
