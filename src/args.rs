use clap::{ArgAction, Parser};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(version)]
pub struct Args {
    /// Increase logging output (can be used multiple times)
    #[arg(short, long, global = true, action(ArgAction::Count))]
    pub verbose: u8,
    pub path: PathBuf,
    #[arg(short = 'b', long, default_value = "var/lib/pacman")]
    pub dbpath: PathBuf,
}
