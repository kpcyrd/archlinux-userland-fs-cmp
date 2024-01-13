pub mod args;
pub mod errors;
pub mod fetch;
pub mod mtree;
pub mod pkg;
pub mod sandbox;

use crate::args::Args;
use crate::errors::*;
use clap::Parser;
use env_logger::Env;
use std::collections::HashMap;
use std::fmt::Write;
use tokio::sync::mpsc;
use tokio::time::{self, Duration};

pub enum Event {
    PkgQueued,
    PkgCompleted,
    TrustedHash(String, String),
    CompletedListInstalled,
    CompletedDiskScan,
    StartedHashing,
    CompletedHashing,
}

#[tokio::main]
async fn run(args: Args) -> Result<()> {
    let dbpath = args.path.join(&args.dbpath);

    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let (http_tx, http_rx) = mpsc::unbounded_channel();

    fetch::spawn_workers(event_tx.clone(), http_rx);
    pkg::spawn_list_installed(event_tx, http_tx, dbpath);

    let mut completed_pkgs = 0;
    let mut total_pkgs = 0;
    let mut trusted_hashes = HashMap::new();

    let mut running_list_installed = true;
    let mut running_disk_scan = true;
    let mut running_hash_workers = 0;

    let mut interval = time::interval(Duration::from_millis(500));

    let mut redraw = true;
    loop {
        tokio::select! {
            event = event_rx.recv() => {
                match event {
                    Some(Event::PkgQueued) => total_pkgs += 1,
                    Some(Event::PkgCompleted) => {
                        completed_pkgs += 1;
                        redraw = true;
                    }
                    Some(Event::TrustedHash(path, sha256)) => {
                        if let Some(old) = trusted_hashes.get(&path) {
                            warn!("Unexpected duplicate for {path:?} ({sha256:?} vs {old:?})");
                        } else {
                            trusted_hashes.insert(path, sha256);
                        }
                    }
                    Some(Event::CompletedListInstalled) => {
                        running_list_installed = false;
                        redraw = true;
                    }
                    Some(Event::CompletedDiskScan) => {
                        running_disk_scan = false;
                        redraw = true;
                    }
                    Some(Event::StartedHashing) => running_hash_workers += 1,
                    Some(Event::CompletedHashing) => running_hash_workers -= 1,
                    // everything has shutdown
                    None => break,
                }
            }
            _ = interval.tick() => {
                redraw = true;
            }
        }

        if redraw {
            let mut status = String::new();
            write!(status, "packages: {completed_pkgs}/{total_pkgs}")?;
            if running_list_installed {
                write!(status, "...")?;
            }

            if trusted_hashes.len() > 0 {
                write!(status, " (files: {})", trusted_hashes.len())?;
            }

            if running_disk_scan {
                write!(status, ", scanning disk...")?;
            }

            write!(status, ", hash workers: {running_hash_workers}/999")?;

            if args.verbose > 0 {
                info!("{status}");
            } else {
                println!("{status}");
            }
            redraw = false;
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();

    let log_level = match args.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    env_logger::init_from_env(Env::default().default_filter_or(log_level));

    // Remove all capabilities we don't need before accessing the filesystem
    sandbox::init()?;

    // Start into tokio and regular program
    run(args)
}
