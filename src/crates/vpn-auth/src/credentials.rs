//! Approved systemd LoadCredential handoff. No root bootstrap or direct secret-file fallback.
use crate::Error;
use ikev2_crypto::SecretBytes;
use rustix::fs::{Mode, OFlags, open, openat};
use std::{fs::File, io::Read, os::unix::fs::MetadataExt, path::Path};
use zeroize::Zeroizing;
pub struct ServiceCredentials {
    pub master_key: SecretBytes,
    pub signing_key: SecretBytes,
    pub certificate_chain: Vec<u8>,
    pub verifiers: Vec<u8>,
}
impl ServiceCredentials {
    pub fn load() -> Result<Self, Error> {
        if rustix::process::geteuid().is_root() {
            return Err(Error::Authentication);
        }
        let path = std::env::var_os("CREDENTIALS_DIRECTORY").ok_or(Error::Authentication)?;
        let path = Path::new(&path);
        let name = credential_unit(path)?;
        let root =
            open("/", directory_flags(), Mode::empty()).map_err(|_| Error::Authentication)?;
        let run = File::from(
            openat(root, "run", directory_flags(), Mode::empty())
                .map_err(|_| Error::Authentication)?,
        );
        trusted_parent(&run)?;
        let base = File::from(
            openat(&run, "credentials", directory_flags(), Mode::empty())
                .map_err(|_| Error::Authentication)?,
        );
        trusted_parent(&base)?;
        let directory = File::from(
            openat(&base, name, directory_flags(), Mode::empty())
                .map_err(|_| Error::Authentication)?,
        );
        let uid = rustix::process::geteuid().as_raw();
        validate_secret(&directory, uid, true)?;
        let master_key = read(&directory, "master-key", 32, uid)?;
        if master_key.expose().len() != 32 {
            return Err(Error::Authentication);
        }
        let signing_key = read(&directory, "server-key", 16384, uid)?;
        let certificate_chain = read(&directory, "server-chain", 65536, uid)?
            .expose()
            .to_vec();
        let verifiers = read(&directory, "verifiers", 200000, uid)?
            .expose()
            .to_vec();
        Ok(Self {
            master_key,
            signing_key,
            certificate_chain,
            verifiers,
        })
    }
}
fn read(directory: &File, name: &str, limit: usize, uid: u32) -> Result<SecretBytes, Error> {
    let fd = openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| Error::Authentication)?;
    let file = File::from(fd);
    let m = file.metadata().map_err(|_| Error::Authentication)?;
    validate_secret(&file, uid, false)?;
    if m.len() == 0 || m.len() > limit as u64 {
        return Err(Error::Authentication);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Authentication)?;
    if bytes.is_empty() || bytes.len() > limit {
        return Err(Error::Authentication);
    }
    Ok(SecretBytes::new(bytes.to_vec()))
}

fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}
fn credential_unit(path: &Path) -> Result<&std::ffi::OsStr, Error> {
    let name = path.file_name().ok_or(Error::Authentication)?;
    // Raw comparison rejects normalized dot components and redundant separators.
    if path.as_os_str() != Path::new("/run/credentials").join(name).as_os_str() {
        return Err(Error::Authentication);
    }
    Ok(name)
}
fn trusted_parent(file: &File) -> Result<(), Error> {
    let m = file.metadata().map_err(|_| Error::Authentication)?;
    if !m.is_dir() || m.uid() != 0 || m.mode() & 0o7022 != 0 {
        return Err(Error::Authentication);
    }
    Ok(())
}
fn validate_secret(file: &File, uid: u32, directory: bool) -> Result<(), Error> {
    let m = file.metadata().map_err(|_| Error::Authentication)?;
    let owner_mode = if directory { 0o500 } else { 0o400 };
    let acl_mode = if directory { 0o550 } else { 0o440 };
    if (directory && !m.is_dir())
        || (!directory && !m.is_file())
        || (m.uid() != 0 && m.uid() != uid)
        || ![owner_mode, acl_mode].contains(&(m.mode() & 0o7777))
    {
        return Err(Error::Authentication);
    }
    // st_mode group bits are the ACL mask. Require systemd's named-UID ACL,
    // with no actual group access, rather than trusting the mask alone.
    let mut acl = [0u8; 128];
    match rustix::fs::fgetxattr(file, "system.posix_acl_access", &mut acl[..]) {
        Ok(len) if valid_acl(&acl[..len], uid, directory) => Ok(()),
        Err(rustix::io::Errno::NODATA | rustix::io::Errno::OPNOTSUPP)
            if m.mode() & 0o7777 == owner_mode =>
        {
            Ok(())
        }
        _ => Err(Error::Authentication),
    }
}
// Linux POSIX ACL xattr v2; accept only the root/service-UID access set.
fn valid_acl(bytes: &[u8], uid: u32, directory: bool) -> bool {
    let permission: u16 = if directory { 5 } else { 4 };
    let expected = [
        (1u16, permission, u32::MAX),
        (2, permission, uid),
        (4, 0, u32::MAX),
        (16, permission, u32::MAX),
        (32, 0, u32::MAX),
    ];
    bytes.len() == 44
        && bytes[..4] == 2u32.to_le_bytes()
        && bytes[4..]
            .chunks_exact(8)
            .zip(expected)
            .all(|(entry, (tag, perm, id))| {
                entry[..2] == tag.to_le_bytes()
                    && entry[2..4] == perm.to_le_bytes()
                    && entry[4..] == id.to_le_bytes()
            })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    fn acl(uid: u32, directory: bool) -> Vec<u8> {
        let permission: u16 = if directory { 5 } else { 4 };
        let mut bytes = 2u32.to_le_bytes().to_vec();
        for (tag, perm, id) in [
            (1u16, permission, u32::MAX),
            (2, permission, uid),
            (4, 0, u32::MAX),
            (16, permission, u32::MAX),
            (32, 0, u32::MAX),
        ] {
            bytes.extend(tag.to_le_bytes());
            bytes.extend(perm.to_le_bytes());
            bytes.extend(id.to_le_bytes());
        }
        bytes
    }
    #[test]
    fn acl_rejects_other_users_groups_writes_and_malformed_entries() {
        for directory in [false, true] {
            let good = acl(1000, directory);
            assert!(valid_acl(&good, 1000, directory));
            assert!(!valid_acl(&good, 1001, directory));
            for index in 0..good.len() {
                let mut bad = good.clone();
                bad[index] ^= 2;
                assert!(!valid_acl(&bad, 1000, directory));
            }
            for len in 0..good.len() {
                assert!(!valid_acl(&good[..len], 1000, directory));
            }
        }
    }
    #[test]
    fn rejects_untrusted_locations() {
        assert!(credential_unit(Path::new("/run/credentials/test.service")).is_ok());
        for path in [
            "/tmp/test",
            "/etc/ikev2lab",
            "/run/credentials",
            "/run/credentials/../test",
            "/run/credentials/./test",
            "/run//credentials/test",
            "/run/credentials/test/",
            "run/credentials/test",
        ] {
            assert!(credential_unit(Path::new(path)).is_err(), "{path}");
        }
    }
    #[test]
    fn systemd_acl_layout_reads_as_nonroot_and_rejects_broad_access() {
        let uid = rustix::process::geteuid().as_raw();
        assert_ne!(uid, 0, "run this test as a nonroot user");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test");
        std::fs::write(&path, [7; 32]).unwrap();
        let file = File::open(&path).unwrap();
        let folder = File::open(dir.path()).unwrap();
        for (fd, directory) in [(&file, false), (&folder, true)] {
            rustix::fs::fsetxattr(
                fd,
                "system.posix_acl_access",
                &acl(uid, directory),
                rustix::fs::XattrFlags::empty(),
            )
            .unwrap();
            validate_secret(fd, uid, directory).unwrap();
            assert_eq!(
                fd.metadata().unwrap().mode() & 0o777,
                if directory { 0o550 } else { 0o440 }
            );
            assert!(validate_secret(fd, uid + 1, directory).is_err());
        }
        assert_eq!(read(&folder, "test", 32, uid).unwrap().expose(), &[7; 32]);
        // A matching numeric mode without an ACL must not grant broad group access.
        rustix::fs::fremovexattr(&file, "system.posix_acl_access").unwrap();
        for mode in [0o440, 0o644, 0o600, 0o444, 0o450, 0o2400] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(read(&folder, "test", 32, uid).is_err());
        }
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    #[test]
    #[ignore = "requires root-owned fixture; see tools/poc/check-credential-layout.py"]
    fn root_owned_systemd_layout() {
        let uid = rustix::process::geteuid().as_raw();
        assert_ne!(uid, 0);
        let path = std::env::var_os("VPN_CREDENTIAL_TEST_DIR").unwrap();
        let folder = File::open(&path).unwrap();
        let file = File::open(Path::new(&path).join("test")).unwrap();
        for (fd, mode) in [(&folder, 0o550), (&file, 0o440)] {
            let m = fd.metadata().unwrap();
            assert_eq!((m.uid(), m.gid(), m.mode() & 0o777), (0, 0, mode));
        }
        validate_secret(&folder, uid, true).unwrap();
        assert_eq!(read(&folder, "test", 32, uid).unwrap().expose(), &[7; 32]);
        assert!(read(&folder, "unreadable", 32, uid).is_err());
    }
    #[test]
    fn copies_reject_permissions_symlinks_oversize_and_missing_data() {
        let dir = tempfile::tempdir().unwrap();
        let folder = File::open(dir.path()).unwrap();
        let uid = rustix::process::geteuid().as_raw();
        let path = dir.path().join("test");
        std::fs::write(&path, [1; 32]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert_eq!(read(&folder, "test", 32, uid).unwrap().expose(), &[1; 32]);
        assert!(read(&folder, "test", 31, uid).is_err());
        assert!(read(&folder, "missing", 32, uid).is_err());
        symlink(&path, dir.path().join("link")).unwrap();
        assert!(read(&folder, "link", 32, uid).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read(&folder, "test", 32, uid).is_err());
    }
}
