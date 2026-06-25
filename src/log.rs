//! Minimal verbosity-gated logging to stderr, mirroring the leveled
//! logging.info/.debug/.warning/.error calls in the Python client.

#[derive(Clone, Copy)]
pub struct Logger {
    /// verbose_count - quiet_count
    pub level: i32,
}

impl Logger {
    pub fn new(verbose: u8, quiet: u8) -> Self {
        Self {
            level: verbose as i32 - quiet as i32,
        }
    }

    pub fn debug(&self, msg: &str) {
        if self.level >= 1 {
            eprintln!("{msg}");
        }
    }

    pub fn info(&self, msg: &str) {
        if self.level >= 0 {
            eprintln!("{msg}");
        }
    }

    pub fn warn(&self, msg: &str) {
        if self.level >= -1 {
            eprintln!("Warning: {msg}");
        }
    }

    pub fn error(&self, msg: &str) {
        if self.level >= -2 {
            eprintln!("Error: {msg}");
        }
    }
}
