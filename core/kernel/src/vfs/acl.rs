//! POSIX ACL entries stored with kernel IDs. The inode mode carries owner, group class and other.
use crate::cred::Cred;
use crate::errno::Errno;
use crate::vfs::store::Stat;

/// The only `system.*` attributes (6.1's `posix_acl_access_xattr_handler` and
/// `posix_acl_default_xattr_handler`, the ones ext4 and tmpfs have).
pub(crate) const ACL_ACCESS: &[u8] = b"system.posix_acl_access";
pub(crate) const ACL_DEFAULT: &[u8] = b"system.posix_acl_default";

// The tags of ACL entries (Linux's `ACL_USER_OBJ` and the rest)
const ACL_USER_OBJ: u16 = 0x01;
pub(crate) const ACL_USER: u16 = 0x02;
const ACL_GROUP_OBJ: u16 = 0x04;
pub(crate) const ACL_GROUP: u16 = 0x08;
const ACL_MASK: u16 = 0x10;
const ACL_OTHER: u16 = 0x20;
/// The ID of entries that name none.
const ACL_UNDEFINED_ID: u32 = u32::MAX;

/// One ACL entry: tag, permissions and ID.
pub(crate) type AclEntry = (u16, u16, u32);

/// An ACL attribute's entries as (tag, permissions, ID), read as `posix_acl_from_xattr` reads
/// them: a header (EINVAL when too short) of version 2 (EOPNOTSUPP otherwise), then 8-byte
/// entries with known tags (EINVAL otherwise).
pub(crate) fn acl_entries(v: &[u8]) -> Result<Vec<AclEntry>, Errno> {
    if v.len() < 4 {
        return Err(Errno::EINVAL);
    }
    if v[..4] != 2u32.to_le_bytes() {
        return Err(Errno::EOPNOTSUPP);
    }
    if !(v.len() - 4).is_multiple_of(8) {
        return Err(Errno::EINVAL);
    }
    v[4..]
        .chunks_exact(8)
        .map(|c| {
            let tag = u16::from_le_bytes([c[0], c[1]]);
            let perm = u16::from_le_bytes([c[2], c[3]]);
            let id = u32::from_le_bytes([c[4], c[5], c[6], c[7]]);
            match tag {
                ACL_USER | ACL_GROUP => Ok((tag, perm, id)),
                ACL_USER_OBJ | ACL_GROUP_OBJ | ACL_MASK | ACL_OTHER => {
                    Ok((tag, perm, ACL_UNDEFINED_ID))
                }
                _ => Err(Errno::EINVAL),
            }
        })
        .collect()
}

/// 6.1's `posix_acl_valid`: permissions within rwx, and the entries in the order owner, named
/// users, owning group, named groups, mask, other, each of the owner, owning group and other once,
/// and a mask when there are named entries.
pub(crate) fn acl_valid(entries: &[AclEntry]) -> Result<(), Errno> {
    let mut state = ACL_USER_OBJ;
    let mut needs_mask = false;
    for &(tag, perm, _) in entries {
        if perm & !7 != 0 {
            return Err(Errno::EINVAL);
        }
        state = match (tag, state) {
            (ACL_USER_OBJ, ACL_USER_OBJ) => ACL_USER,
            (ACL_USER, ACL_USER) => {
                needs_mask = true;
                ACL_USER
            }
            (ACL_GROUP_OBJ, ACL_USER) => ACL_GROUP,
            (ACL_GROUP, ACL_GROUP) => {
                needs_mask = true;
                ACL_GROUP
            }
            (ACL_MASK, ACL_GROUP) => ACL_OTHER,
            (ACL_OTHER, ACL_OTHER) => 0,
            (ACL_OTHER, ACL_GROUP) if !needs_mask => 0,
            _ => return Err(Errno::EINVAL),
        };
    }
    if state == 0 {
        Ok(())
    } else {
        Err(Errno::EINVAL)
    }
}

/// The attribute form of ACL entries (`posix_acl_to_xattr`).
pub(crate) fn acl_encode(entries: &[AclEntry]) -> Vec<u8> {
    let mut v = 2u32.to_le_bytes().to_vec();
    for &(tag, perm, id) in entries {
        v.extend_from_slice(&tag.to_le_bytes());
        v.extend_from_slice(&perm.to_le_bytes());
        v.extend_from_slice(&id.to_le_bytes());
    }
    v
}

/// The mode bits represented by these validated entries. The mask is the group class
/// of an extended ACL, including one with no named entries.
pub(crate) fn mode_bits(entries: &[AclEntry]) -> u32 {
    let mut bits = 0;
    for &(tag, perm, _) in entries {
        let p = u32::from(perm);
        match tag {
            ACL_USER_OBJ => bits |= p << 6,
            ACL_GROUP_OBJ | ACL_MASK => bits = (bits & !0o070) | (p << 3),
            ACL_OTHER => bits |= p,
            _ => {}
        }
    }
    bits
}

/// Change the classes represented by the inode mode. Inheritance intersects the
/// parent's permissions with the requested mode; chmod replaces them.
pub(crate) fn apply_mode(entries: &mut [AclEntry], mode: u32, inherit: bool) {
    let masked = entries.iter().any(|e| e.0 == ACL_MASK);
    for (tag, perm, _) in entries {
        let shift = match *tag {
            ACL_USER_OBJ => 6,
            ACL_GROUP_OBJ if !masked => 3,
            ACL_MASK => 3,
            ACL_OTHER => 0,
            _ => continue,
        };
        let class = ((mode >> shift) & 7) as u16;
        *perm = if inherit { *perm & class } else { class };
    }
}

pub(crate) fn extended(entries: &[AclEntry]) -> bool {
    entries
        .iter()
        .any(|e| matches!(e.0, ACL_USER | ACL_GROUP | ACL_MASK))
}

/// Permission of a non-owner. One matching group entry must grant the whole request.
pub(crate) fn allows(entries: &[AclEntry], cred: &Cred, st: &Stat, need: u32) -> bool {
    let class = (st.mode >> 3) & 7;
    let mut matched_group = false;
    for &(tag, perm, id) in entries {
        let grants = need & !(u32::from(perm) & class) == 0;
        let gid = match tag {
            ACL_USER if cred.fsuid == id => return grants,
            ACL_GROUP_OBJ => st.gid,
            ACL_GROUP => id,
            ACL_OTHER => return !matched_group && need & !u32::from(perm) == 0,
            _ => continue,
        };
        if cred.in_group(gid) {
            if grants {
                return true;
            }
            matched_group = true;
        }
    }
    false
}

/// Install a newly created inode's inherited ACLs inside its creation transaction.
pub(crate) fn inherit(
    store: &super::store::Store,
    ino: u64,
    default: &[AclEntry],
) -> Result<(), Errno> {
    acl_valid(default)?;
    let st = store.attrs(ino)?;
    if st.is_dir() {
        store.set_xattr(ino, ACL_DEFAULT, &acl_encode(default), false, false)?;
    }
    let mut access = default.to_vec();
    apply_mode(&mut access, st.mode, true);
    let mode = st.mode & !0o777 | mode_bits(&access);
    if mode != st.mode {
        store.set_mode(ino, mode)?;
    }
    if extended(&access) {
        store.set_xattr(ino, ACL_ACCESS, &acl_encode(&access), false, false)?;
    }
    Ok(())
}
