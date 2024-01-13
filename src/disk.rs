use crate::errors::*;
use crate::Event;
// use async_walkdir::{Filtering, WalkDir};
use walkdir::WalkDir;
// use futures_util::StreamExt;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::task;
// use std::path::Path;
use std::path::PathBuf;
// use tokio::fs;
use std::sync::Mutex;
use tokio::sync::mpsc;

const NUM_HASH_WORKERS: usize = 4;

pub fn spawn_scan(
    event_tx: mpsc::UnboundedSender<Event>,
    path: PathBuf,
    excluded: HashSet<PathBuf>,
) -> usize {
    tokio::spawn(async move {
        let mut walkdir = Arc::new(Mutex::new(WalkDir::new(path).into_iter()));

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

    NUM_HASH_WORKERS
}
