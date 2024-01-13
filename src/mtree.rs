use crate::errors::*;

#[derive(Debug, PartialEq)]
pub struct Entry {
    pub path: String,
    pub time: String,
    pub content: EntryType,
}

#[derive(Debug, PartialEq)]
pub enum EntryType {
    File(File),
    Directory(Directory),
    Link(Link),
}

#[derive(Debug, PartialEq)]
pub struct File {
    pub size: u64,
    // do not consider mtree without md5 invalid
    pub md5digest: Option<String>,
    pub sha256digest: String,
}

#[derive(Debug, PartialEq)]
pub struct Directory {}

#[derive(Debug, PartialEq)]
pub struct Link {
    pub mode: String,
    pub link: String,
}

pub fn parse(line: &str) -> Option<Entry> {
    if !line.starts_with('.') {
        return None;
    }

    let mut time = None;
    let mut size = None;
    let mut md5digest = None;
    let mut sha256digest = None;
    let mut mode = None;
    let mut t = None;
    let mut link = None;

    let (path, metadata) = line.split_once(' ')?;
    for md in metadata.split(' ') {
        if let Some((key, value)) = md.split_once('=') {
            match key {
                "time" => time = Some(value.to_string()),
                "size" => {
                    let value = value.parse().ok()?;
                    size = Some(value);
                }
                "md5digest" => md5digest = Some(value.to_string()),
                "sha256digest" => sha256digest = Some(value.to_string()),
                "mode" => mode = Some(value.to_string()),
                "type" => t = Some(value.to_string()),
                "link" => link = Some(value.to_string()),
                _ => (),
            }
        }
    }

    let content = match t.as_deref() {
        None => EntryType::File(File {
            size: size?,
            md5digest,
            sha256digest: sha256digest?,
        }),
        Some("dir") => EntryType::Directory(Directory {}),
        Some("link") => EntryType::Link(Link {
            mode: mode?,
            link: link?,
        }),
        Some(t) => {
            warn!("Unknown mtree type: {t:?}");
            return None;
        }
    };

    Some(Entry {
        path: path.to_string(),
        time: time?,
        content,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_file() {
        let line = "./usr/lib/signal-desktop/signal-desktop time=1704931316.0 size=171753536 md5digest=a301a912dd0206dbfb43241d0a95bc4a sha256digest=e25add8820bcc151001e8720722a582b22586f4ac11a1a24a42606f7dc8511e6";
        let entry = parse(line);
        assert_eq!(
            entry,
            Some(Entry {
                path: "./usr/lib/signal-desktop/signal-desktop".to_string(),
                time: "1704931316.0".to_string(),
                content: EntryType::File(File {
                    size: 171753536,
                    md5digest: Some("a301a912dd0206dbfb43241d0a95bc4a".to_string()),
                    sha256digest:
                        "e25add8820bcc151001e8720722a582b22586f4ac11a1a24a42606f7dc8511e6"
                            .to_string(),
                }),
            })
        );
    }

    #[test]
    fn parse_directory() {
        let line = "./usr/lib/signal-desktop time=1704931316.0 type=dir";
        let entry = parse(line);
        assert_eq!(
            entry,
            Some(Entry {
                path: "./usr/lib/signal-desktop".to_string(),
                time: "1704931316.0".to_string(),
                content: EntryType::Directory(Directory {}),
            })
        );
    }

    #[test]
    fn parse_link() {
        let line = "./usr/bin/signal-desktop time=1704931316.0 mode=777 type=link link=/usr/lib/signal-desktop/signal-desktop";
        let entry = parse(line);
        assert_eq!(
            entry,
            Some(Entry {
                path: "./usr/bin/signal-desktop".to_string(),
                time: "1704931316.0".to_string(),
                content: EntryType::Link(Link {
                    mode: "777".to_string(),
                    link: "/usr/lib/signal-desktop/signal-desktop".to_string(),
                }),
            })
        );
    }
}
