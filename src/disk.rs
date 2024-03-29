use crate::errors::*;
use crate::Event;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::FileType;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::task;
use walkdir::{DirEntry, WalkDir};

#[derive(Debug)]
pub enum HashVerify {
    Passed(PathBuf),
    Flagged(PathBuf),
}

async fn verify_file(path: &Path, sha256: &str) -> Result<bool> {
    let mut file = File::open(path).await?;
    let mut hasher = Sha256::new();

    let expected = hex::decode(sha256)
        .with_context(|| anyhow!("Failed to decode sha256 as hex: {sha256:?}"))?;

    let mut buf = [0u8; 2048];
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let calculated = hasher.finalize();

    if expected == calculated[..] {
        Ok(true)
    } else {
        Ok(false)
    }
}

pub async fn read_disk(
    walkdir: &std::sync::Mutex<walkdir::IntoIter>,
    entry: std::result::Result<DirEntry, walkdir::Error>,
    excluded: &HashSet<PathBuf>,
) -> Result<Option<(PathBuf, FileType)>> {
    let entry = entry.context("Failed to access disk")?;

    let path = entry.path().to_owned();
    if excluded.contains(&path) {
        let mut lock = walkdir.lock().unwrap();
        lock.skip_current_dir();
        return Ok(None);
    }

    let stat = task::spawn_blocking(move || entry.file_type())
        .await
        .with_context(|| anyhow!("Failed to stat path {path:?}"))?;

    Ok(Some((path, stat)))
}

pub fn spawn_scan(
    event_tx: mpsc::UnboundedSender<Event>,
    path: PathBuf,
    excluded: HashSet<PathBuf>,
    num_hash_workers: usize,
) {
    // wait for paths and their expected hash, then verify with disk content
    for _ in 0..num_hash_workers {
        let event_tx = event_tx.clone();
        tokio::spawn(async move {
            loop {
                let (tx, rx) = oneshot::channel();
                if event_tx.send(Event::AvailableHasher(tx)).is_err() {
                    break;
                }
                let Ok((path, sha256)) = rx.await else { break };

                let event = match verify_file(&path, &sha256).await {
                    Ok(verified) => Event::CompletedHashing(if verified {
                        HashVerify::Passed(path)
                    } else {
                        HashVerify::Flagged(path)
                    }),
                    Err(err) => {
                        Event::DiskError(anyhow!("Failed to read file from disk {path:?}: {err:#}"))
                    }
                };

                if event_tx.send(event).is_err() {
                    break;
                }
            }
        });
    }

    // walk the filesystem and report to main thread
    tokio::spawn(async move {
        let walkdir = Arc::new(std::sync::Mutex::new(WalkDir::new(path).into_iter()));

        loop {
            let Ok(Some(entry)) = ({
                let walkdir = walkdir.clone();
                task::spawn_blocking(move || {
                    let mut lock = walkdir.lock().unwrap();
                    lock.next()
                })
                .await
            }) else {
                break;
            };

            let event = match read_disk(&walkdir, entry, &excluded).await {
                Ok(Some((path, stat))) => {
                    if stat.is_dir() {
                        Event::DiskPwd(path)
                    } else if stat.is_symlink() {
                        // ignore this for now
                        continue;
                    } else {
                        Event::DiskFile(path)
                    }
                }
                Ok(None) => continue,
                Err(err) => Event::DiskError(err),
            };

            if event_tx.send(event).is_err() {
                return;
            }
        }

        event_tx.send(Event::CompletedDiskScan).ok();
    });
}
