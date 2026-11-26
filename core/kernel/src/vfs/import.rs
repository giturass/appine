//! Imports a rootfs tar.gz into the inode store (the android/setup map).
//!
//! The whole import is done in one transaction, keeping permission bits (setuid included),
//! owners, mtimes, symlinks and hardlinks. Paths are resolved only in the store's namespace, so
//! `..`, absolute paths and symlinks pointing outside in the tar never touch the host filesystem
//! (§12 item 3).

use std::borrow::Cow;
use std::io::{self, Read};

use flate2::read::GzDecoder;

use crate::cred::{FileCaps, XATTR_NAME_CAPS};
use crate::errno::Errno;
use crate::vfs::acl::{self, ACL_ACCESS, ACL_DEFAULT};
use crate::vfs::store::{Ino, ROOT, Store, mode};

/// Prefix used by PAX extended headers (GNU tar `--xattrs`, libarchive/bsdtar, OCI layers) for
/// extended attributes.
const PAX_XATTR_PREFIX: &[u8] = b"SCHILY.xattr.";
/// Maximum xattr name and value sizes matching `syscall/xattr.rs`.
const XATTR_NAME_MAX: usize = 255;
const XATTR_SIZE_MAX: usize = 65536;

/// Import statistics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ImportReport {
    /// Number of directories.
    pub dirs: u64,
    /// Number of regular files.
    pub files: u64,
    /// Number of symlinks.
    pub symlinks: u64,
    /// Number of hardlinks.
    pub hardlinks: u64,
    /// Number of device nodes and FIFOs.
    pub nodes: u64,
}

/// Imports from a gzip-compressed tar stream.
pub fn import_tar_gz(store: &Store, reader: impl Read) -> Result<ImportReport, Errno> {
    store.transaction(|store| {
        let mut archive = tar::Archive::new(GzDecoder::new(reader));
        let mut report = ImportReport::default();
        // Directory mtimes are set last: creating entries in a directory later would set its mtime
        // to now (GNU tar does the same)
        let mut dir_times = Vec::new();
        let entries = archive.entries().map_err(tar_err)?;
        for entry in entries {
            let mut entry = entry.map_err(tar_err)?;
            let path = entry.path_bytes().into_owned();
            let comps = components(&path)?;
            let xattrs = extract_xattrs(&mut entry)?;
            let header = entry.header();
            let perm = header.mode().map_err(tar_err)? & 0o7777;
            let uid = header.uid().map_err(tar_err)? as u32;
            let gid = header.gid().map_err(tar_err)? as u32;
            let mtime_ns = header.mtime().map_err(tar_err)? as i64 * 1_000_000_000;
            let kind = header.entry_type();
            let Some((name, parents)) = comps.split_last() else {
                // The root directory in the tar: only update its attributes
                store.set_owner_mode(ROOT, perm, uid, gid)?;
                apply_xattrs(store, ROOT, mode::S_IFDIR, &xattrs)?;
                dir_times.push((ROOT, mtime_ns));
                continue;
            };
            let parent = ensure_dir(store, parents, &mut report)?;
            let existing = store.lookup(parent, name)?;

            let (ino, file_type) = if kind.is_dir() {
                let ino = match existing {
                    Some(ino) => ino,
                    None => {
                        report.dirs += 1;
                        store.mkdir(parent, name, perm, uid, gid)?
                    }
                };
                store.set_owner_mode(ino, perm, uid, gid)?;
                apply_xattrs(store, ino, mode::S_IFDIR, &xattrs)?;
                dir_times.push((ino, mtime_ns));
                continue;
            } else if existing.is_some() {
                return Err(Errno::EEXIST);
            } else if kind.is_file() {
                report.files += 1;
                let (ino, mut file) = store.create_file(parent, name, perm, uid, gid)?;
                io::copy(&mut entry, &mut file).map_err(tar_err)?;
                (ino, mode::S_IFREG)
            } else if kind.is_symlink() {
                report.symlinks += 1;
                let target = entry.link_name_bytes().ok_or(Errno::EINVAL)?.into_owned();
                (
                    store.symlink(parent, name, &target, uid, gid)?,
                    mode::S_IFLNK,
                )
            } else if kind.is_hard_link() {
                report.hardlinks += 1;
                let target = entry.link_name_bytes().ok_or(Errno::EINVAL)?.into_owned();
                let target_comps = components(&target)?;
                let mut ino = ROOT;
                for c in &target_comps {
                    ino = store.lookup(ino, c)?.ok_or(Errno::ENOENT)?;
                }
                store.link(parent, name, ino)?;
                continue;
            } else if kind.is_character_special() || kind.is_block_special() || kind.is_fifo() {
                report.nodes += 1;
                let ty = if kind.is_character_special() {
                    mode::S_IFCHR
                } else if kind.is_block_special() {
                    mode::S_IFBLK
                } else {
                    mode::S_IFIFO
                };
                let major = header.device_major().ok().flatten().unwrap_or(0) as u64;
                let minor = header.device_minor().ok().flatten().unwrap_or(0) as u64;
                let rdev = (major << 8 & 0xfff00) | (minor & 0xff) | (minor << 12 & !0xfffff);
                (store.mknod(parent, name, ty | perm, rdev, uid, gid)?, ty)
            } else {
                continue; // metadata entries such as pax headers
            };
            apply_xattrs(store, ino, file_type, &xattrs)?;
            store.set_mtime(ino, mtime_ns)?;
        }
        for (ino, mtime_ns) in dir_times {
            store.set_mtime(ino, mtime_ns)?;
        }
        Ok(report)
    })
}

fn tar_err(e: io::Error) -> Errno {
    crate::debug::log(format_args!("rootfs import: {e}"));
    Errno::EIO
}

/// An extended attribute `(name, value)` extracted from a PAX header.
type Xattr = (Vec<u8>, Vec<u8>);

/// Extracts `SCHILY.xattr.<name>` PAX extended attributes from a tar entry.
fn extract_xattrs(entry: &mut tar::Entry<'_, impl Read>) -> Result<Vec<Xattr>, Errno> {
    let Some(exts) = entry.pax_extensions().map_err(tar_err)? else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for ext in exts {
        let ext = ext.map_err(tar_err)?;
        if let Some(name) = ext.key_bytes().strip_prefix(PAX_XATTR_PREFIX) {
            out.push((name.to_vec(), ext.value_bytes().to_vec()));
        }
    }
    Ok(out)
}

/// Stores supported PAX xattrs on `ino`, skipping unsupported namespaces, invalid capabilities or
/// ACLs, and xattrs disallowed for `file_type`.
fn apply_xattrs(store: &Store, ino: Ino, file_type: u32, xattrs: &[Xattr]) -> Result<(), Errno> {
    for (name, value) in xattrs {
        if let Some(encoded) = filter_xattr(name, value, file_type) {
            store.set_xattr(ino, name, &encoded, false, false)?;
        }
    }
    Ok(())
}

fn filter_xattr<'a>(name: &[u8], value: &'a [u8], file_type: u32) -> Option<Cow<'a, [u8]>> {
    if name.len() > XATTR_NAME_MAX || name.contains(&0) || value.len() > XATTR_SIZE_MAX {
        return None;
    }
    if let Some(rest) = name.strip_prefix(b"security.") {
        if rest.is_empty() || (name == XATTR_NAME_CAPS && !FileCaps::valid_xattr(value)) {
            return None;
        }
        return Some(Cow::Borrowed(value));
    }
    if name
        .strip_prefix(b"trusted.")
        .is_some_and(|r| !r.is_empty())
    {
        return Some(Cow::Borrowed(value));
    }
    if name.strip_prefix(b"user.").is_some_and(|r| !r.is_empty()) {
        return matches!(file_type, mode::S_IFREG | mode::S_IFDIR).then_some(Cow::Borrowed(value));
    }
    if name == ACL_ACCESS || name == ACL_DEFAULT {
        if file_type == mode::S_IFLNK || (name == ACL_DEFAULT && file_type != mode::S_IFDIR) {
            return None;
        }
        let entries = acl::acl_entries(value).ok()?;
        acl::acl_valid(&entries).ok()?;
        if name == ACL_ACCESS && !acl::extended(&entries) {
            return None;
        }
        return Some(Cow::Owned(acl::acl_encode(&entries)));
    }
    None
}

/// Splits a path into components, dropping empty components, `.` and the leading `/`; EINVAL on
/// `..`.
fn components(path: &[u8]) -> Result<Vec<&[u8]>, Errno> {
    let mut out = Vec::new();
    for c in path.split(|&b| b == b'/') {
        match c {
            b"" | b"." => {}
            b".." => return Err(Errno::EINVAL),
            c => out.push(c),
        }
    }
    Ok(out)
}

/// Finds (creating it if needed) the directory for a path, without following symlinks.
fn ensure_dir(store: &Store, comps: &[&[u8]], report: &mut ImportReport) -> Result<Ino, Errno> {
    let mut dir = ROOT;
    for c in comps {
        dir = match store.lookup(dir, c)? {
            Some(ino) => ino,
            None => {
                report.dirs += 1;
                store.mkdir(dir, c, 0o755, 0, 0)?
            }
        };
    }
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tar_gz(build: impl FnOnce(&mut tar::Builder<Vec<u8>>)) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        build(&mut builder);
        let raw = builder.into_inner().unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut gz, &raw).unwrap();
        gz.finish().unwrap()
    }

    fn header(kind: tar::EntryType, mode: u32, size: u64) -> tar::Header {
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(kind);
        h.set_mode(mode);
        h.set_size(size);
        h.set_mtime(1_700_000_000);
        h.set_uid(0);
        h.set_gid(0);
        h
    }

    #[test]
    fn imports_files_links_and_modes() {
        let data = tar_gz(|b| {
            b.append_data(
                &mut header(tar::EntryType::Directory, 0o755, 0),
                "./bin/",
                &[][..],
            )
            .unwrap();
            b.append_data(
                &mut header(tar::EntryType::Regular, 0o4755, 5),
                "./bin/busybox",
                &b"hello"[..],
            )
            .unwrap();
            let mut l = header(tar::EntryType::Symlink, 0o777, 0);
            b.append_link(&mut l, "./bin/ls", "/bin/busybox").unwrap();
            let mut h = header(tar::EntryType::Link, 0o755, 0);
            b.append_link(&mut h, "./sbin/bb", "./bin/busybox").unwrap();
        });
        let dir = std::env::temp_dir().join(format!("appine-import-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::create(&dir).unwrap();
        let report = import_tar_gz(&store, &data[..]).unwrap();
        assert_eq!((report.files, report.symlinks, report.hardlinks), (1, 1, 1));

        let bin = store.lookup(ROOT, b"bin").unwrap().unwrap();
        let busybox = store.lookup(bin, b"busybox").unwrap().unwrap();
        let st = store.stat(busybox).unwrap();
        assert_eq!((st.mode, st.size, st.nlink), (mode::S_IFREG | 0o4755, 5, 2));
        assert_eq!(st.mtime_ns, 1_700_000_000 * 1_000_000_000);
        // The directory's mtime is the one from the tar, not the time entries were created in it
        assert_eq!(
            store.stat(bin).unwrap().mtime_ns,
            1_700_000_000 * 1_000_000_000
        );
        let ls = store.lookup(bin, b"ls").unwrap().unwrap();
        assert_eq!(store.readlink(ls).unwrap(), b"/bin/busybox");
        let sbin = store.lookup(ROOT, b"sbin").unwrap().unwrap();
        assert_eq!(store.lookup(sbin, b"bb").unwrap(), Some(busybox));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_parent_components() {
        assert_eq!(components(b"./a/../b"), Err(Errno::EINVAL));
        assert_eq!(components(b"/a//b/.").unwrap(), vec![&b"a"[..], &b"b"[..]]);
    }

    #[test]
    fn imports_pax_xattrs_and_file_capabilities() {
        use crate::cred::Cred;

        // v2 security.capability: effective + CAP_NET_RAW (bit 13) in permitted set.
        let mut cap_v2 = [0u8; 20];
        cap_v2[..4].copy_from_slice(&0x0200_0001u32.to_le_bytes());
        cap_v2[4..8].copy_from_slice(&(1u32 << 13).to_le_bytes());

        // v3 security.capability with rootid 100000 and CAP_NET_BIND_SERVICE (bit 10).
        let mut cap_v3 = [0u8; 24];
        cap_v3[..4].copy_from_slice(&0x0300_0001u32.to_le_bytes());
        cap_v3[4..8].copy_from_slice(&(1u32 << 10).to_le_bytes());
        cap_v3[20..24].copy_from_slice(&100_000u32.to_le_bytes());

        // Valid extended POSIX ACL (owner rwx, named user 1000 r-x, group r-x, mask r-x, other r-x).
        let ext_acl = acl::acl_encode(&[
            (0x01, 7, u32::MAX),
            (0x02, 5, 1000),
            (0x04, 5, u32::MAX),
            (0x10, 5, u32::MAX),
            (0x20, 5, u32::MAX),
        ]);

        let add = |b: &mut tar::Builder<Vec<u8>>,
                   kind: tar::EntryType,
                   path: &str,
                   body: &[u8],
                   xattrs: &[(&str, &[u8])]| {
            b.append_pax_extensions(xattrs.iter().copied()).unwrap();
            b.append_data(&mut header(kind, 0o755, body.len() as u64), path, body)
                .unwrap();
        };

        let data = tar_gz(|b| {
            add(
                b,
                tar::EntryType::Directory,
                "./",
                b"",
                &[("SCHILY.xattr.user.root", b"yes")],
            );
            add(
                b,
                tar::EntryType::Directory,
                "./etc/",
                b"",
                &[
                    ("SCHILY.xattr.user.dir", b"etc-val"),
                    ("SCHILY.xattr.trusted.tag", b"dir-tag"),
                    ("SCHILY.xattr.system.posix_acl_default", &ext_acl),
                ],
            );
            add(
                b,
                tar::EntryType::Regular,
                "./bin/ping",
                b"ELF\0",
                &[
                    ("SCHILY.xattr.security.capability", &cap_v2),
                    (
                        "SCHILY.xattr.security.selinux",
                        b"system_u:object_r:ping_t:s0\0",
                    ),
                    ("SCHILY.xattr.user.comment", b"ping binary"),
                    ("SCHILY.xattr.system.posix_acl_access", &ext_acl),
                    ("SCHILY.xattr.unknown.ignored", b"skip"),
                ],
            );
            add(
                b,
                tar::EntryType::Regular,
                "./bin/capv3",
                b"ok",
                &[("SCHILY.xattr.security.capability", &cap_v3)],
            );
            add(
                b,
                tar::EntryType::Regular,
                "./bin/badcap",
                b"no",
                &[("SCHILY.xattr.security.capability", b"bad!")],
            );

            b.append_pax_extensions([
                ("SCHILY.xattr.user.on_link", &b"disallowed"[..]),
                ("SCHILY.xattr.trusted.on_link", &b"allowed"[..]),
                ("SCHILY.xattr.system.posix_acl_access", &ext_acl[..]),
            ])
            .unwrap();
            let mut l = header(tar::EntryType::Symlink, 0o777, 0);
            b.append_link(&mut l, "./bin/link", "/bin/ping").unwrap();
        });

        let dir = std::env::temp_dir().join(format!("appine-import-xattr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::create(&dir).unwrap();
        import_tar_gz(&store, &data[..]).unwrap();

        // Root and directory xattrs + default ACL
        assert_eq!(store.get_xattr(ROOT, b"user.root").unwrap(), b"yes");
        let etc = store.lookup(ROOT, b"etc").unwrap().unwrap();
        assert_eq!(store.get_xattr(etc, b"user.dir").unwrap(), b"etc-val");
        assert_eq!(store.get_xattr(etc, b"trusted.tag").unwrap(), b"dir-tag");
        assert_eq!(store.get_xattr(etc, ACL_DEFAULT).unwrap(), ext_acl);

        // Regular file with v2 capabilities, security/user xattrs, and extended access ACL
        let bin = store.lookup(ROOT, b"bin").unwrap().unwrap();
        let ping = store.lookup(bin, b"ping").unwrap().unwrap();
        assert!(store.has_file_caps(ping).unwrap());
        let stored_cap = store.get_xattr(ping, XATTR_NAME_CAPS).unwrap();
        assert_eq!(stored_cap, cap_v2);
        let parsed = FileCaps::parse(&stored_cap, &Cred::root())
            .unwrap()
            .unwrap();
        assert!(parsed.effective);
        assert_eq!(parsed.permitted, 1u64 << 13);
        assert_eq!(
            store.get_xattr(ping, b"security.selinux").unwrap(),
            b"system_u:object_r:ping_t:s0\0"
        );
        assert_eq!(
            store.get_xattr(ping, b"user.comment").unwrap(),
            b"ping binary"
        );
        assert_eq!(store.get_xattr(ping, ACL_ACCESS).unwrap(), ext_acl);
        assert_eq!(
            store.get_xattr(ping, b"unknown.ignored"),
            Err(Errno::ENODATA)
        );
        assert!(store.attrs(ping).unwrap().access_acl.is_some());

        // v3 capabilities stored verbatim; invalid capability blob skipped
        let capv3_ino = store.lookup(bin, b"capv3").unwrap().unwrap();
        assert!(store.has_file_caps(capv3_ino).unwrap());
        assert_eq!(store.get_xattr(capv3_ino, XATTR_NAME_CAPS).unwrap(), cap_v3);
        let badcap = store.lookup(bin, b"badcap").unwrap().unwrap();
        assert!(!store.has_file_caps(badcap).unwrap());
        assert_eq!(
            store.get_xattr(badcap, XATTR_NAME_CAPS),
            Err(Errno::ENODATA)
        );

        // Symlink: trusted.* preserved, user.* and POSIX ACL skipped
        let link = store.lookup(bin, b"link").unwrap().unwrap();
        assert_eq!(
            store.get_xattr(link, b"trusted.on_link").unwrap(),
            b"allowed"
        );
        assert_eq!(store.get_xattr(link, b"user.on_link"), Err(Errno::ENODATA));
        assert_eq!(store.get_xattr(link, ACL_ACCESS), Err(Errno::ENODATA));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
