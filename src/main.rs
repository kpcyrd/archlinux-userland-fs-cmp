pub mod args;
pub mod disk;
pub mod errors;
pub mod fetch;
pub mod mtree;
pub mod pkg;
pub mod sandbox;

use crate::args::Args;
use crate::disk::HashVerify;
use crate::errors::*;
use clap::Parser;
use colored::{Color, Colorize};
use env_logger::Env;
use num_format::{Locale, ToFormattedString};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Write;
use std::path::PathBuf;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::time::{self, Duration};

const PATH_TRUNCATE: usize = 85;

pub enum Event {
    PkgQueued,
    PkgCompleted,
    TrustedFile(PathBuf, String),
    DiskFile(PathBuf),
    DiskPwd(PathBuf),
    CompletedListInstalled,
    CompletedDiskScan,
    AvailableHasher(oneshot::Sender<(PathBuf, String)>),
    CompletedHashing(HashVerify),
}

#[tokio::main]
async fn run(args: Args) -> Result<()> {
    let dbpath = args.path.join(&args.dbpath);

    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let (http_tx, http_rx) = mpsc::unbounded_channel();

    fetch::spawn_workers(event_tx.clone(), http_rx);
    pkg::spawn_list_installed(event_tx.clone(), http_tx, dbpath);
    let excluded = args.exclude.into_iter().collect();
    let num_hash_worker = args.concurrency.unwrap_or_else(num_cpus::get);
    disk::spawn_scan(event_tx, args.path, excluded, num_hash_worker);

    let mut completed_pkgs = 0;
    let mut total_pkgs = 0;
    let mut trusted_hashes = HashMap::new();

    let mut running_list_installed = true;
    let mut running_disk_scan = true;

    let mut waiting_for_data = HashSet::new();
    let mut waiting_for_hasher = VecDeque::new();
    let mut available_hashers = VecDeque::new();
    let mut files_passed = 0;
    let mut files_flagged = 0;

    let mut disk_pwd = None;

    let mut interval = time::interval(if args.verbose == 0 {
        Duration::from_millis(500)
    } else {
        Duration::from_secs(3)
    });

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
                    Some(Event::TrustedFile(path, sha256)) => {
                        if let Some(old) = trusted_hashes.get(&path) {
                            warn!("Unexpected duplicate for {path:?} ({sha256:?} vs {old:?})");
                        } else {
                            if waiting_for_data.remove(&path) {
                                waiting_for_hasher.push_back((path.clone(), sha256.clone()));
                            }
                            trusted_hashes.insert(path, sha256);
                        }
                    }
                    Some(Event::DiskFile(path)) => {
                        if let Some(sha256) = trusted_hashes.get(&path) {
                            waiting_for_hasher.push_back((path, sha256.clone()));
                        } else {
                            waiting_for_data.insert(path);
                        }
                    }
                    Some(Event::DiskPwd(path)) => {
                        disk_pwd = Some(path);
                    }
                    Some(Event::CompletedListInstalled) => {
                        running_list_installed = false;
                        redraw = true;
                    }
                    Some(Event::CompletedDiskScan) => {
                        running_disk_scan = false;
                        disk_pwd = None;
                        redraw = true;
                    }
                    Some(Event::AvailableHasher(hasher)) => {
                        available_hashers.push_back(hasher);
                    }
                    Some(Event::CompletedHashing(hashed)) => match hashed {
                        HashVerify::Passed(_) => files_passed += 1,
                        HashVerify::Flagged(_) => files_flagged += 1,
                    }
                    // everything has shutdown
                    None => break,
                }
            }
            _ = interval.tick() => {
                redraw = true;
            }
        }

        while !waiting_for_hasher.is_empty() && !available_hashers.is_empty() {
            let hasher = available_hashers.pop_front().unwrap();
            let task = waiting_for_hasher.pop_front().unwrap();
            if hasher.send(task).is_err() {
                warn!("All hashers have crashed");
                return Ok(());
            }
        }

        while !available_hashers.is_empty()
            && waiting_for_hasher.is_empty()
            && !running_disk_scan
            && completed_pkgs == total_pkgs
        {
            available_hashers.pop_front();
        }

        if redraw {
            let mut status = "packages: ".bold().to_string();
            status.push_str(
                &format!("{:>7}", completed_pkgs.to_formatted_string(&Locale::en))
                    .color(if completed_pkgs < total_pkgs {
                        Color::Yellow
                    } else {
                        Color::Green
                    })
                    .to_string(),
            );
            status.push_str(&"/".bold().to_string());
            status.push_str(
                &total_pkgs
                    .to_formatted_string(&Locale::en)
                    .bold()
                    .to_string(),
            );
            if running_list_installed {
                status.push_str("...");
            }

            if !trusted_hashes.is_empty() {
                status.push_str(
                    &format!(
                        " (files: {:>7})",
                        trusted_hashes.len().to_formatted_string(&Locale::en)
                    )
                    .bright_black()
                    .to_string(),
                );
            }

            status.push_str(&" | scanned disk: ".bold().to_string());
            status.push_str(
                &format!(
                    "{:>8}",
                    waiting_for_data.len().to_formatted_string(&Locale::en)
                )
                .yellow()
                .to_string(),
            );
            if running_disk_scan {
                status.push_str("...");
            }
            status.push('/');
            status.push_str(&format!(
                "{:>7}",
                waiting_for_hasher.len().to_formatted_string(&Locale::en)
            ));

            status.push_str(&" | hashing ".bold().to_string());
            {
                let running_hash_workers = num_hash_worker - available_hashers.len();
                let s = format!("{running_hash_workers}/{num_hash_worker}");
                let s = if running_hash_workers == num_hash_worker {
                    s.cyan()
                } else if running_hash_workers == 0 {
                    s.bright_black()
                } else {
                    s.normal()
                }
                .to_string();
                write!(status, "[{s}]")?;
            }

            status.push_str(&" | passed".bold().to_string());
            status.push('=');
            status.push_str(
                &files_passed
                    .to_formatted_string(&Locale::en)
                    .green()
                    .to_string(),
            );
            status.push_str(&" failed".bold().to_string());
            status.push('=');
            status.push_str(
                &files_flagged
                    .to_formatted_string(&Locale::en)
                    .red()
                    .to_string(),
            );

            if let Some(path) = &disk_pwd {
                let path = format!("{:?}", path.display());

                let mut offset = 0;
                let mut width = 0;
                let mut truncated = false;
                for c in path.chars() {
                    width += unicode_width::UnicodeWidthChar::width(c).unwrap_or(1);
                    if width < PATH_TRUNCATE {
                        offset += c.len_utf8();
                    } else {
                        truncated = true;
                        break;
                    }
                }

                let path = &path[..offset];
                let truncated = if truncated { "..." } else { "" };
                status.push_str(&format!(" ({path}{truncated})").bright_black().to_string());
            }

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
