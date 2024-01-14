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
    /// Files and folder to exclude (won't be traversed)
    #[arg(short = 'x', long)]
    pub exclude: Vec<PathBuf>,
    /// How many files to hash concurrently
    #[arg(short = 'n', long)]
    pub concurrency: Option<usize>,
}
