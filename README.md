# archlinux-userland-fs-cmp

Forensic tool to read all installed packages from a mounted Arch Linux drive and compare the filesystem to a trusted source. This utilizes https://archive.archlinux.org, all files not coming from one of those packages are flagged for investigation.

## Features

- Not the entire package is fetched from the archive, as soon as the `.MTREE` has been received the download is aborted. This currently relies on https for security (which is considered acceptable for what it's written for), but for added security could be pointed to an ipfs folder (that has been calculated/authenticated ahead of time).
- The mounted filesystem is hashed with a thread pool.
- The scan needs `CAP_DAC_READ_SEARCH` which usually requires root, but before accessing the mounted filesystem all unneeded kernel capabilities are removed (like `CAP_SYS_ADMIN`, `CAP_SETUID`, `CAP_DAC_OVERRIDE`, ...) and the process is then blocked from re-acquiring them.
- The mounted filesystem is considered untrusted and may contain malicious changes, parsers are written in memory-safe languages and files are only read, but never executed.
- The investigating live medium can be any Linux, like Debian or NixOS.

## Usage

```sh
archlinux-userland-fs-cmp /mnt -x /home -o ~/report.txt
```

This expects an Arch Linux install to be mounted on `/mnt` and is going to exclude `/mnt/home` from the scan.

## Testing for development

For development, you may find this command useful:

```sh
cargo watch -- cargo run --release -- / -x /home -x /dev -x /proc -x /sys -x /run -x /var/cache # -x /var/lib/archbuild -x /nix -x /var/lib/repro ...
```

## Why not paccheck?

pacman can do it's own integrity checks using:

```
paccheck --sha256sum --quiet
```

However, the Arch Linux wiki states:

> Note: This should **not** be used as is when suspecting malicious changes! In this case security precautions such as using a live medium and an independent source for the hash sums are advised.

archlinux-userland-fs-cmp implements this accordingly (use from a live medium is still advised of course).
