use crate::errors::*;
use crate::mtree;
use crate::pkg::Package;
use crate::Event;
use async_compression::tokio::bufread::{GzipDecoder, XzDecoder, ZstdDecoder};
use async_stream::stream;
use futures_core::stream::Stream;
use futures_util::{pin_mut, StreamExt, TryStreamExt};
use reqwest::StatusCode;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use tokio::io::{self, AsyncBufRead, AsyncBufReadExt, AsyncRead, BufReader, ReadBuf};
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tokio_tar as tar;
use tokio_util::compat::FuturesAsyncReadCompatExt;

const NUM_HTTP_WORKERS: usize = 4;

fn remote_tar_read_mtree<R: AsyncRead + Unpin>(
    reader: R,
) -> impl Stream<Item = Result<mtree::Entry>> {
    stream! {
        let mut tar = tar::Archive::new(reader);
        let mut entries = tar.entries()?;

        while let Some(entry) = entries.next().await {
            let entry = entry?;

            if entry.header().entry_type() != tar::EntryType::Regular {
                continue;
            }

            let path = entry
                .header()
                .path()
                .context("Filename was not valid utf-8")?;

            let Some(name) = path.file_name() else {
                continue;
            };

            debug!("Found path in remote tar file: {path:?} => {name:?}");
            if name == ".MTREE" {
                let f = BufReader::new(entry);
                let f = GzipDecoder::new(f);
                let f = BufReader::new(f);
                let mut f = f.lines();

                while let Some(line) = f
                    .next_line()
                    .await
                    .context("Failed to read line from .MTREE")?
                {
                    if let Some(entry) = mtree::parse(&line) {
                        yield Ok(entry);
                    }
                }

                return;
            }
        }

        yield Err(anyhow!("Failed to find .MTREE in package"));
    }
}

pub enum Decompress<R> {
    Zst(ZstdDecoder<R>),
    Xz(XzDecoder<R>),
}

impl<R: AsyncBufRead + Unpin> AsyncRead for Decompress<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut *self {
            Decompress::Zst(inner) => Pin::new(inner).poll_read(cx, buf),
            Decompress::Xz(inner) => Pin::new(inner).poll_read(cx, buf),
        }
    }
}

async fn fetch_remote_mtree(
    client: &reqwest::Client,
    url: &str,
    compression: &str,
) -> Result<Option<impl Stream<Item = Result<mtree::Entry>>>> {
    info!("Fetching url {url:?}");
    let res = client
        .get(url)
        .send()
        .await
        .with_context(|| anyhow!("Failed to send http request ({url:?})"))?;

    let status = res.status();
    debug!("Received {status:?}, processing response...");
    let bytes = res.bytes_stream();
    let mut bytes = bytes
        .map_err(|e| futures::io::Error::new(futures::io::ErrorKind::Other, e))
        .into_async_read()
        .compat();

    if !status.is_success() {
        // read the response to reuse connection (but discard the data)
        io::copy(&mut bytes, &mut io::sink()).await.ok();

        if status == StatusCode::NOT_FOUND {
            Ok(None)
        } else {
            bail!("HTTP request failed with status {status:?}: {url:?}");
        }
    } else {
        let bytes = BufReader::new(bytes);

        let reader = match compression {
            "zst" => Decompress::Zst(ZstdDecoder::new(bytes)),
            "xz" => Decompress::Xz(XzDecoder::new(bytes)),
            _ => bail!("Unsupported compression format: {compression:?}"),
        };

        Ok(Some(remote_tar_read_mtree(reader)))
    }
}

async fn fetch_trusted_hashes<'a>(
    client: &'a reqwest::Client,
    pkg: &'a Package,
) -> impl Stream<Item = (String, String)> + 'a {
    stream! {
        for ext in ["zst", "xz"] {
            let Some(first) = pkg.name.chars().next() else {
                continue;
            };
            let pkgname = &pkg.name;
            let pkgver = &pkg.version;
            let arch = &pkg.arch;
            let url = format!("https://archive.archlinux.org/packages/{first}/{pkgname}/{pkgname}-{pkgver}-{arch}.pkg.tar.{ext}");

            match fetch_remote_mtree(client, &url, ext).await {
                Ok(Some(mtree)) => {
                    pin_mut!(mtree);

                    while let Some(entry) = mtree.next().await {
                        if let Ok(entry) = entry {
                            let path = entry.path;
                            if let mtree::EntryType::File(file) = entry.content {
                                yield (path.clone(), file.sha256digest);
                            }
                        }
                    }

                    break;
                }
                Ok(None) => (),
                Err(err) => {
                    warn!("Failed to fetch remote mtree: {err:#}");
                }
            }
        }
    }
}

pub fn spawn_workers(
    event_tx: mpsc::UnboundedSender<Event>,
    rx: mpsc::UnboundedReceiver<Package>,
    root: &Path,
) {
    let rx = Arc::new(Mutex::new(rx));
    for _ in 0..NUM_HTTP_WORKERS {
        let root = root.to_owned();
        let rx = rx.clone();
        let event_tx = event_tx.clone();
        tokio::spawn(async move {
            let client = reqwest::Client::new();

            loop {
                let pkg = {
                    let mut lock = rx.lock().await;
                    lock.recv().await
                };
                let Some(pkg) = pkg else { break };

                let stream = fetch_trusted_hashes(&client, &pkg).await;
                pin_mut!(stream);
                while let Some((path, sha256)) = stream.next().await {
                    match path.as_str() {
                        "./.BUILDINFO" => continue,
                        "./.PKGINFO" => continue,
                        "./.INSTALL" => continue,
                        "./.CHANGELOG" => continue,
                        _ => (),
                    }
                    debug!("Found path in package: {path:?} (sha256={sha256:?}");
                    if !path.starts_with("./") {
                        warn!("Found malformed path in .MTREE: {path:?}");
                        continue;
                    }
                    let path = root.join(path);
                    if event_tx.send(Event::TrustedFile(path, sha256)).is_err() {
                        // shutdown worker
                        return;
                    }
                }

                if event_tx.send(Event::PkgCompleted).is_err() {
                    break;
                }
            }
        });
    }
}
