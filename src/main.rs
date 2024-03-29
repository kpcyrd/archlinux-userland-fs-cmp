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
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::io::Write;
use std::path::PathBuf;
use tokio::fs::File;
use tokio::io::{self, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::time::{self, Duration};

const PATH_TRUNCATE: usize = 85;

#[derive(Debug)]
pub enum Event {
    PkgQueued,
    PkgCompleted,
    TrustedFile(PathBuf, String),
    DiskFile(PathBuf),
    DiskPwd(PathBuf),
    DiskError(Error),
    CompletedListInstalled,
    CompletedDiskScan,
    AvailableHasher(oneshot::Sender<(PathBuf, String)>),
    CompletedHashing(HashVerify),
}

#[derive(Default)]
pub struct App {
    num_hash_worker: usize,
    retired_hashers: usize,

    completed_pkgs: u64,
    total_pkgs: u64,
    trusted_hashes: HashMap<PathBuf, String>,

    running_list_installed: bool,
    running_disk_scan: bool,

    waiting_for_data: BTreeSet<PathBuf>,
    waiting_for_hasher: VecDeque<(PathBuf, String)>,
    available_hashers: VecDeque<oneshot::Sender<(PathBuf, String)>>,

    files_passed: u64,
    files_flagged: BTreeSet<PathBuf>,

    disk_errors: Vec<Error>,
    disk_pwd: Option<PathBuf>,
}

impl App {
    fn new(num_hash_worker: usize) -> Self {
        Self {
            num_hash_worker,
            running_list_installed: true,
            running_disk_scan: true,
            ..Default::default()
        }
    }

    fn update(&mut self, event: Event) -> bool {
        match event {
            Event::PkgQueued => self.total_pkgs += 1,
            Event::PkgCompleted => {
                self.completed_pkgs += 1;
                return true;
            }
            Event::TrustedFile(path, sha256) => {
                if let Some(old) = self.trusted_hashes.get(&path) {
                    warn!("Unexpected duplicate for {path:?} ({sha256:?} vs {old:?})");
                } else {
                    if self.waiting_for_data.remove(&path) {
                        self.waiting_for_hasher
                            .push_back((path.clone(), sha256.clone()));
                    }
                    self.trusted_hashes.insert(path, sha256);
                }
            }
            Event::DiskFile(path) => {
                if let Some(sha256) = self.trusted_hashes.get(&path) {
                    self.waiting_for_hasher.push_back((path, sha256.clone()));
                } else {
                    self.waiting_for_data.insert(path);
                }
            }
            Event::DiskPwd(path) => {
                self.disk_pwd = Some(path);
            }
            Event::DiskError(err) => {
                self.disk_errors.push(err);
            }
            Event::CompletedListInstalled => {
                self.running_list_installed = false;
                return true;
            }
            Event::CompletedDiskScan => {
                self.running_disk_scan = false;
                self.disk_pwd = None;
                return true;
            }
            Event::AvailableHasher(hasher) => {
                self.available_hashers.push_back(hasher);
            }
            Event::CompletedHashing(hashed) => match hashed {
                HashVerify::Passed(_) => self.files_passed += 1,
                HashVerify::Flagged(path) => {
                    self.files_flagged.insert(path);
                }
            },
        }

        false
    }

    fn redraw(&self, logs_enabled: bool) {
        let mut status = "packages: ".bold().to_string();
        status.push_str(
            &format!(
                "{:>7}",
                self.completed_pkgs.to_formatted_string(&Locale::en)
            )
            .color(if self.completed_pkgs < self.total_pkgs {
                Color::Yellow
            } else {
                Color::Green
            })
            .to_string(),
        );
        status.push_str(&"/".bold().to_string());
        status.push_str(
            &self
                .total_pkgs
                .to_formatted_string(&Locale::en)
                .bold()
                .to_string(),
        );
        if self.running_list_installed {
            status.push_str("...");
        }

        if !self.trusted_hashes.is_empty() {
            status.push_str(
                &format!(
                    " (files: {:>7})",
                    self.trusted_hashes.len().to_formatted_string(&Locale::en)
                )
                .bright_black()
                .to_string(),
            );
        }

        status.push_str(&" | scanned disk: ".bold().to_string());
        status.push_str(
            &format!(
                "{:>8}",
                self.waiting_for_data.len().to_formatted_string(&Locale::en)
            )
            .yellow()
            .to_string(),
        );
        if self.running_disk_scan {
            status.push_str("...");
        }
        status.push('/');
        status.push_str(&format!(
            "{:>7}",
            self.waiting_for_hasher
                .len()
                .to_formatted_string(&Locale::en)
        ));

        status.push_str(&" | hashing ".bold().to_string());
        {
            let running_hash_workers =
                self.num_hash_worker - self.retired_hashers - self.available_hashers.len();
            let s = format!("{running_hash_workers}/{}", self.num_hash_worker);
            let s = if running_hash_workers == self.num_hash_worker {
                s.cyan()
            } else if running_hash_workers == 0 {
                s.bright_black()
            } else {
                s.normal()
            }
            .to_string();
            status.push('[');
            status.push_str(&s);
            status.push(']');
        }

        status.push_str(&" | passed".bold().to_string());
        status.push('=');
        status.push_str(
            &self
                .files_passed
                .to_formatted_string(&Locale::en)
                .green()
                .to_string(),
        );
        status.push_str(&" failed".bold().to_string());
        status.push('=');
        status.push_str(
            &self
                .files_flagged
                .len()
                .to_formatted_string(&Locale::en)
                .red()
                .to_string(),
        );

        if let Some(path) = &self.disk_pwd {
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

        if logs_enabled {
            info!("{status}");
        } else {
            println!("{status}");
        }
    }
}

#[tokio::main]
async fn run(args: Args) -> Result<()> {
    let dbpath = args.path.join(&args.dbpath);

    // ensure we can correctly open the file for reporting
    let mut writer = if let Some(path) = args.output {
        Box::new(
            File::create(&path)
                .await
                .with_context(|| anyhow!("Failed to open file: {path:?}"))?,
        ) as Box<dyn AsyncWrite + Unpin>
    } else {
        Box::new(io::stdout()) as Box<dyn AsyncWrite + Unpin>
    };

    // setup scan
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let (http_tx, http_rx) = mpsc::unbounded_channel();

    fetch::spawn_workers(event_tx.clone(), http_rx, &args.path);
    pkg::spawn_list_installed(event_tx.clone(), http_tx, dbpath);
    let excluded = args
        .exclude
        .iter()
        .map(PathBuf::as_path)
        .map(|mut p| {
            while let Ok(v) = p.strip_prefix("/") {
                p = v;
            }
            args.path.join(p)
        })
        .collect();
    let num_hash_worker = args.concurrency.unwrap_or_else(num_cpus::get);
    disk::spawn_scan(event_tx, args.path, excluded, num_hash_worker);

    let mut app = App::new(num_hash_worker);

    let mut interval = time::interval(if args.verbose == 0 {
        Duration::from_millis(500)
    } else {
        Duration::from_secs(3)
    });

    let mut redraw = true;
    loop {
        tokio::select! {
            event = event_rx.recv() => {
                if let Some(event) = event {
                    if app.update(event) {
                        redraw = true;
                    }
                } else {
                    // everything has shutdown
                    break
                }
            }
            _ = interval.tick() => {
                redraw = true;
            }
        }

        while !app.waiting_for_hasher.is_empty() && !app.available_hashers.is_empty() {
            let hasher = app.available_hashers.pop_front().unwrap();
            let task = app.waiting_for_hasher.pop_front().unwrap();
            if hasher.send(task).is_err() {
                warn!("All hashers have crashed");
                return Ok(());
            }
        }

        while !app.available_hashers.is_empty()
            && app.waiting_for_hasher.is_empty()
            && !app.running_disk_scan
            && app.completed_pkgs == app.total_pkgs
        {
            app.available_hashers.pop_front();
            app.retired_hashers += 1;
        }

        if redraw {
            app.redraw(args.verbose > 0);
            redraw = false;
        }
    }

    // redraw one final time
    app.redraw(args.verbose > 0);

    // write report
    let mut buf = Vec::new();
    for path in app.waiting_for_data {
        writeln!(buf, "[NO SHA256] {path:?}")?;
        writer
            .write_all(&buf)
            .await
            .context("Failed to write report")?;
        buf.clear();
    }
    for err in app.disk_errors {
        writeln!(buf, "[DISK ERROR] {err:#}")?;
        writer
            .write_all(&buf)
            .await
            .context("Failed to write report")?;
        buf.clear();
    }
    for path in app.files_flagged {
        writeln!(buf, "[WRONG SHA256] {path:?}")?;
        writer
            .write_all(&buf)
            .await
            .context("Failed to write report")?;
        buf.clear();
    }

    Ok(())
}

#[tokio::main]
async fn list_pkgs(args: Args) -> Result<()> {
    let dbpath = args.path.join(&args.dbpath);

    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let (http_tx, mut http_rx) = mpsc::unbounded_channel();

    pkg::spawn_list_installed(event_tx, http_tx, dbpath);

    let client = reqwest::Client::new();
    loop {
        tokio::select! {
            Some(_msg) = event_rx.recv() => (),
            Some(pkg) = http_rx.recv() => {
                let mut found = false;

                for ext in fetch::PKG_COMPRESSION_EXTS {
                    let Ok(url) = pkg.to_url(ext) else { continue };
                    if fetch::head(&client, &url).await?.is_success() {
                        println!("{url}");
                        found = true;
                        break;
                    }
                }

                if !found {
                    bail!("Failed to determine url for pkg: {pkg:?}");
                }
            }
            else => break,
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
    if args.list_pkgs {
        list_pkgs(args)
    } else {
        run(args)
    }
}
