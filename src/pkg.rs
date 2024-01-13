use crate::errors::*;
use crate::Event;
use async_stream::stream;
use async_walkdir::WalkDir;
use futures_core::stream::Stream;
use futures_util::{pin_mut, StreamExt};
use std::path::Path;
use std::path::PathBuf;
use tokio::fs;
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub arch: String,
}

pub fn list_installed(path: &Path) -> impl Stream<Item = Result<Package>> {
    let path = path.join("local");

    stream! {
        let mut entries = WalkDir::new(path);

        while let Some(entry) = entries.next().await {
            let entry = entry.context("Failed to read from pacman database")?;
            let stat = entry
                .file_type()
                .await
                .with_context(|| anyhow!("Failed to determine file type of {:?}", entry.path()))?;

            if stat.is_dir() {
                continue;
            }

            if entry.file_name().to_str() != Some("desc") {
                continue;
            }

            let path = entry.path();
            let desc = fs::read_to_string(&path).await
                .with_context(|| anyhow!("Failed to read file: {path:?}"))?;

            let mut name = None;
            let mut version = None;
            let mut arch = None;

            for section in desc.split("\n\n") {
                let section = section.split('\n').collect::<Vec<_>>();

                match (section.first(), section.len()) {
                    (Some(&"%NAME%"), 2) => name = Some(section[1]),
                    (Some(&"%VERSION%"), 2) => version = Some(section[1]),
                    (Some(&"%ARCH%"), 2) => arch = Some(section[1]),
                    _ => (),
                }
            }

            if let (Some(name), Some(version), Some(arch)) = (name, version, arch) {
                yield Ok(Package {
                    name: name.to_string(),
                    version: version.to_string(),
                    arch: arch.to_string(),
                })
            }
        }
    }
}

pub fn spawn_list_installed(
    event_tx: mpsc::UnboundedSender<Event>,
    tx: mpsc::UnboundedSender<Package>,
    dbpath: PathBuf,
) {
    tokio::spawn(async move {
        let s = list_installed(&dbpath);
        pin_mut!(s);

        while let Some(pkg) = s.next().await {
            match pkg {
                Ok(pkg) => {
                    debug!("Found installed package: {:?} {:?}", pkg.name, pkg.version);
                    if event_tx.send(Event::PkgQueued).is_err() {
                        break;
                    }
                    if tx.send(pkg).is_err() {
                        warn!("All http workers have crashed");
                        break;
                    }
                }
                Err(err) => warn!("Failed to read installed packages: {err:#?}"),
            }
        }

        event_tx.send(Event::CompletedListInstalled).ok();
    });
}
