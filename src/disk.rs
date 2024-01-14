use crate::errors::*;
use crate::Event;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::task;
use walkdir::WalkDir;

pub enum HashVerify {
    Passed(PathBuf),
    Flagged(PathBuf),
}

async fn verify_file(path: &Path, sha256: &str) -> Result<()> {
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
        Ok(())
    } else {
        bail!("sha256 mismatch")
    }
}

pub fn spawn_scan(
    event_tx: mpsc::UnboundedSender<Event>,
    path: PathBuf,
    excluded: HashSet<PathBuf>,
    num_hash_workers: usize,
) {
    for _ in 0..num_hash_workers {
        let event_tx = event_tx.clone();
        tokio::spawn(async move {
            loop {
                let (tx, rx) = oneshot::channel();
                if event_tx.send(Event::AvailableHasher(tx)).is_err() {
                    break;
                }
                let Ok((path, sha256)) = rx.await else { break };

                let verify = if verify_file(&path, &sha256).await.is_ok() {
                    HashVerify::Passed(path)
                } else {
                    HashVerify::Flagged(path)
                };

                if event_tx.send(Event::CompletedHashing(verify)).is_err() {
                    break;
                }
            }
        });
    }

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

            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    warn!("Failed to access disk: {err:#}");
                    continue;
                }
            };

            let path = entry.path().to_owned();
            if excluded.contains(&path) {
                let mut lock = walkdir.lock().unwrap();
                lock.skip_current_dir();
                continue;
            }

            let stat = task::spawn_blocking(move || entry.file_type()).await;

            let stat = match stat {
                Ok(stat) => stat,
                Err(err) => {
                    warn!("Failed to stat path {path:?}: {err:#}");
                    continue;
                }
            };

            let event = if stat.is_dir() {
                Event::DiskPwd(path)
            } else {
                Event::DiskFile(path)
            };

            if event_tx.send(event).is_err() {
                return;
            }
        }

        event_tx.send(Event::CompletedDiskScan).ok();
    });
}
