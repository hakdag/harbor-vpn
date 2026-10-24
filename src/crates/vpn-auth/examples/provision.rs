//! Offline root-only provisioning. Build as an ordinary user; run the reviewed binary
//! with stdin piped from systemd-ask-password. Never pass a password in argv/env.
use ikev2_crypto::{SecretBytes, mschap::MschapProvider};
use std::{
    error::Error,
    fs::{File, OpenOptions},
    io::{IsTerminal, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;
fn read_master(path: &Path) -> Result<SecretBytes, Box<dyn Error>> {
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    let mut f = File::from(fd);
    let m = f.metadata()?;
    if !m.is_file() || m.uid() != 0 || m.mode() & 0o777 != 0o600 || m.len() != 32 {
        return Err("master key must be root-owned 0600 and exactly 32 bytes".into());
    }
    let mut data = Zeroizing::new(vec![0; 32]);
    f.read_exact(&mut data)?;
    Ok(SecretBytes::new(data.to_vec()))
}
fn main() -> Result<(), Box<dyn Error>> {
    if !rustix::process::geteuid().is_root() {
        return Err("provisioning requires root; the VPN daemon must run nonroot".into());
    }
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 3 {
        return Err(
            "usage: provision MASTER_KEY USERNAME NEW_ENCRYPTED_FILE; password on protected stdin"
                .into(),
        );
    }
    let key_path = PathBuf::from(&args[0]);
    let output = PathBuf::from(&args[2]);
    if !key_path.is_absolute() || !output.is_absolute() {
        return Err("absolute paths outside source control required".into());
    }
    let parent = output
        .parent()
        .ok_or("output parent required")?
        .canonicalize()?;
    if parent.ancestors().any(|p| p.join(".git").exists())
        || parent.starts_with(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .ancestors()
                .nth(3)
                .ok_or("build path")?,
        )
    {
        return Err("refusing secret output in a source repository".into());
    }
    let pm = std::fs::metadata(&parent)?;
    if pm.uid() != 0 || pm.mode() & 0o077 != 0 {
        return Err("output directory must be root-owned 0700 or stricter".into());
    }
    let name = args[1].to_str().ok_or("username encoding")?.as_bytes();
    if !vpn_auth::valid_username(name) {
        return Err("unsupported username syntax".into());
    }
    if std::io::stdin().is_terminal() {
        return Err(
            "use systemd-ask-password pipe; direct terminal password input is disabled".into(),
        );
    }
    let mut password = Zeroizing::new(Vec::new());
    std::io::stdin().take(1025).read_to_end(&mut password)?;
    if password.last() == Some(&b'\n') {
        password.pop();
    }
    if password.last() == Some(&b'\r') {
        password.pop();
    }
    let text = std::str::from_utf8(&password)?;
    if password.len() > 1024 || text.chars().count() < 20 || text.chars().any(char::is_control) {
        return Err("password must have at least 20 characters, without control characters".into());
    }
    let master = read_master(&key_path)?;
    let hash = MschapProvider::new()?.nt_hash(text)?;
    let record = vpn_auth::encrypt_user(&master, name, true, &hash)?;
    let encrypted = vpn_auth::encode_file(&[record])?;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(parent.join(output.file_name().ok_or("output filename")?))?;
    f.write_all(&encrypted)?;
    f.sync_all()?;
    println!("Encrypted single-user lab verifier created; no password or hash was printed.");
    Ok(())
}
