//! The private keys the tests sign with. None is in the repository (no file
//! that is named private or holds a private key is pushed): the first test that needs one makes
//! it with `openssl`, under `tests/fixtures/` of this checkout - `.gitignore` keeps it out - or
//! in a directory of the user's own under the temp directory when the crate's own directory
//! cannot be written (a copy from a registry). A key that is there is used as it is. They sign
//! test tokens and test SAML responses and nothing else. The documents the SAML verifier is
//! tested against are made the same way where they are missing (`saml/fixture_gen.rs`), with
//! keys that do not outlive the making.
#![allow(dead_code)] // which of the two keys a build uses is a matter of its features

use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use base64::Engine;

/// The ES256 key of the tests' identity provider: PKCS#8 PEM, and its public point as a JWK's x and y
pub(crate) struct EcKey {
    pub pem: String,
    pub x: String,
    pub y: String,
}

/// The RSA key the tests' SAML responses are signed with, and the certificate that verifies them
pub(crate) struct Signer {
    pub key_pem: String,
    pub cert_pem: String,
}

pub(crate) fn ec() -> &'static EcKey {
    static KEY: OnceLock<EcKey> = OnceLock::new();
    KEY.get_or_init(|| there_or_made(load_ec, make_ec))
}

pub(crate) fn signer() -> &'static Signer {
    static KEY: OnceLock<Signer> = OnceLock::new();
    KEY.get_or_init(|| there_or_made(load_signer, make_signer))
}

const EC_PEM: &str = "ec_p256_private.pem";
const EC_X: &str = "ec_p256_jwk_x.txt";
const EC_Y: &str = "ec_p256_jwk_y.txt";
const SIGNER_KEY: &str = "saml/signer_key.pem";
const SIGNER_CERT: &str = "saml/signer_cert.pem";
const LOCK: &str = ".keys.lock";

/// Where the keys are looked for, and made: this checkout first, then the user's own directory
/// under the temp directory.
fn dirs() -> Vec<PathBuf> {
    let mut dirs = vec![Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")];
    dirs.extend(own_temp_dir());
    dirs
}

/// [review 2026-11-15] The fallback is the user's alone: `signon-test-keys-<uid>` under the temp
/// directory, made 0700, and used only when it is this user's and nobody else can write or read
/// it. A directory somebody else put there - with keys of their choosing - is not used.
fn own_temp_dir() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt};
        // whose files this process makes: the owner of one it makes now
        let probe = std::env::temp_dir().join(format!(".signon-uid-{}-{:?}", std::process::id(), std::thread::current().id()));
        std::fs::write(&probe, b"").ok()?;
        let uid = std::fs::metadata(&probe).map(|m| m.uid());
        let _ = std::fs::remove_file(&probe);
        let uid = uid.ok()?;
        let dir = std::env::temp_dir().join(format!("signon-test-keys-{uid}"));
        match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
            Ok(()) => Some(dir),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                let m = std::fs::symlink_metadata(&dir).ok()?;
                (m.is_dir() && m.uid() == uid && m.mode() & 0o077 == 0).then_some(dir)
            }
            Err(_) => None,
        }
    }
    #[cfg(not(unix))]
    {
        Some(std::env::temp_dir().join("signon-test-keys"))
    }
}

/// The key a directory already holds, else one made in the first directory that can be written.
/// Two test processes may ask at once: one makes it, under a lock, and the other finds it there.
pub(crate) fn there_or_made<T>(load: fn(&Path) -> Option<T>, make: fn(&Path) -> io::Result<()>) -> T {
    let dirs = dirs();
    if let Some(key) = dirs.iter().find_map(|d| load(d)) {
        return key;
    }
    let mut why = String::new();
    for dir in &dirs {
        let made = locked(dir, || match load(dir) {
            Some(key) => Ok(key),
            None => make(dir).and_then(|()| load(dir).ok_or_else(|| io::Error::other("made, and not readable"))),
        });
        match made {
            Ok(key) => return key,
            Err(e) => why = format!("{}: {e}", dir.display()),
        }
    }
    panic!("the test keys are not in the repository and could not be made - `openssl` is needed: {why}");
}

/// `f` with the directory's lock held: an exclusive lock on a file in it, which the system gives
/// back when its holder ends, however it ends. [review 2026-11-15, the second] The lock was a
/// directory with its holder's pid inside: a panic in `f` kept it, so the next ask in the same
/// process waited for itself for ever, and two takers of a stale one could both hold it. With a
/// file lock there is nothing to take over.
pub(crate) fn locked<T>(dir: &Path, f: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    std::fs::create_dir_all(dir.join("saml"))?;
    let path = dir.join(LOCK);
    if path.is_dir() {
        let _ = std::fs::remove_dir_all(&path); // the lock of the first version of this file
    }
    let lock = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(&path)?;
    lock.lock()?; // given back when `lock` is dropped: at the return, and when a panic unwinds
    sweep(dir);
    f()
}

/// [review 2026-11-15, the second] What a making that was killed left behind - a private key
/// under its temp name among it - is removed by the next one. Under the lock no other making
/// goes on in this directory, so every such file is a dead run's.
fn sweep(dir: &Path) {
    for d in [dir.to_path_buf(), dir.join("saml")] {
        for entry in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if (name.starts_with(".private-") || name.starts_with(".making-")) && name.ends_with(".tmp") {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
}

/// A file that is not private, whole or not there: written under a temp name, then renamed.
/// [review 2026-11-15, the second] The file whose presence says a set is whole was written in
/// place, and a reader could find it half written.
pub(crate) fn write_whole(file: &Path, bytes: &[u8]) -> io::Result<()> {
    let name = file.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let tmp = file.with_file_name(format!(".making-{name}-{}.tmp", std::process::id()));
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, file)
}

fn load_ec(dir: &Path) -> Option<EcKey> {
    let read = |name: &str| std::fs::read_to_string(dir.join(name)).ok();
    Some(EcKey { pem: read(EC_PEM)?, x: read(EC_X)?.trim().to_string(), y: read(EC_Y)?.trim().to_string() })
}

fn load_signer(dir: &Path) -> Option<Signer> {
    let read = |name: &str| std::fs::read_to_string(dir.join(name)).ok();
    Some(Signer { key_pem: read(SIGNER_KEY)?, cert_pem: read(SIGNER_CERT)? })
}

/// [review 2026-11-15] A private key while it is being made. Its name has "private" in it, which
/// `.gitignore` keeps out of the repository under `tests/fixtures`; it is its owner's alone from
/// the moment it exists, before `openssl` writes a byte to it; and it is removed when the making
/// stops short of [`PrivateTemp::keep_as`] - an error, or a panic.
pub(crate) struct PrivateTemp(PathBuf);

impl PrivateTemp {
    pub(crate) fn new(dir: &Path, what: &str) -> io::Result<PrivateTemp> {
        let path = dir.join(format!(".private-{what}-{}.tmp", std::process::id()));
        let _ = std::fs::remove_file(&path); // one a run with this pid left, long ago
        let mut open = std::fs::OpenOptions::new();
        open.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            open.mode(0o600);
        }
        open.open(&path)?;
        Ok(PrivateTemp(path))
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }

    /// The key under its own name: the last step, so a set that is found is whole
    fn keep_as(self, name: &Path) -> io::Result<()> {
        owner_only(&self.0)?;
        std::fs::rename(&self.0, name)
        // dropped next: the temp name is gone already, and removing it again is nothing
    }
}

impl Drop for PrivateTemp {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// A new P-256 key and its public point, the key file last
fn make_ec(dir: &Path) -> io::Result<()> {
    let tmp = PrivateTemp::new(dir, "ec")?;
    openssl(&["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out"], &tmp.0)?;
    // SubjectPublicKeyInfo of a P-256 key ends with the point, uncompressed: 04, X, Y
    let spki = openssl(&["pkey", "-pubout", "-outform", "DER", "-in"], &tmp.0)?;
    let point = spki.len().checked_sub(65).map(|at| &spki[at..]).filter(|p| p[0] == 4)
        .ok_or_else(|| io::Error::other("no P-256 point in what openssl wrote"))?;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    std::fs::write(dir.join(EC_X), b64.encode(&point[1..33]) + "\n")?;
    std::fs::write(dir.join(EC_Y), b64.encode(&point[33..]) + "\n")?;
    tmp.keep_as(&dir.join(EC_PEM))
}

/// A new RSA key and its self-signed certificate, the key file last
fn make_signer(dir: &Path) -> io::Result<()> {
    let tmp = PrivateTemp::new(&dir.join("saml"), "signer")?;
    openssl(&["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out"], &tmp.0)?;
    let cert = openssl(&["req", "-x509", "-new", "-sha256", "-days", "36500", "-subj", "/CN=signon test signer", "-key"], &tmp.0)?;
    std::fs::write(dir.join(SIGNER_CERT), cert)?;
    tmp.keep_as(&dir.join(SIGNER_KEY))
}

/// `openssl <args> <file>`: what it wrote to its output
pub(crate) fn openssl(args: &[&str], file: &Path) -> io::Result<Vec<u8>> {
    let out = Command::new("openssl").args(args).arg(file).output()?;
    if out.status.success() {
        Ok(out.stdout)
    } else {
        Err(io::Error::other(format!("openssl {}: {}", args[0], String::from_utf8_lossy(&out.stderr).trim())))
    }
}

/// A private key is its owner's to read, whatever the umask
fn owner_only(file: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o600))?;
    }
    let _ = file;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("signon-keys-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut left: Vec<String> = std::fs::read_dir(dir).unwrap().chain(std::fs::read_dir(dir.join("saml")).unwrap())
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        left.sort();
        left
    }

    #[cfg(unix)]
    fn mode(file: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(file).unwrap().permissions().mode() & 0o777
    }

    /// A directory with no key gets a whole set of each kind, the private files their owner's
    /// alone; asked again, it is the same set - nothing is made twice
    #[test]
    fn keys_are_made_once_where_there_are_none() {
        let dir = scratch("made");
        assert!(load_ec(&dir).is_none() && load_signer(&dir).is_none());
        locked(&dir, || make_ec(&dir).and_then(|()| make_signer(&dir))).expect("openssl makes the keys");

        let ec = load_ec(&dir).expect("the EC set");
        assert!(ec.pem.starts_with("-----BEGIN PRIVATE KEY-----"), "PKCS#8");
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        assert_eq!(b64.decode(&ec.x).unwrap().len(), 32);
        assert_eq!(b64.decode(&ec.y).unwrap().len(), 32);
        let signer = load_signer(&dir).expect("the signer's key and certificate");
        assert!(signer.key_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(signer.cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        #[cfg(unix)]
        for private in [EC_PEM, SIGNER_KEY] {
            assert_eq!(mode(&dir.join(private)), 0o600, "{private}");
        }
        // nothing but the set and the lock's file is left: no temp file of the making
        assert_eq!(names(&dir), [".keys.lock", "ec_p256_jwk_x.txt", "ec_p256_jwk_y.txt", "ec_p256_private.pem", "saml", "signer_cert.pem", "signer_key.pem"]);

        // a second ask finds them: the same bytes
        let again = load_ec(&dir).unwrap();
        assert_eq!((again.pem, again.x, again.y), (ec.pem, ec.x, ec.y));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// [review 2026-11-15] a key in the making is named so that `.gitignore` keeps it out, is its
    /// owner's alone before anything is written to it, and is gone when the making stops short
    #[test]
    fn a_key_in_the_making_is_private_and_does_not_outlive_a_failure() {
        let dir = scratch("temp");
        std::fs::create_dir_all(dir.join("saml")).unwrap();
        let tmp = PrivateTemp::new(&dir, "ec").unwrap();
        let path = tmp.0.clone();
        assert!(path.file_name().unwrap().to_string_lossy().contains("private"), "the ignore pattern is *private*");
        assert_eq!(std::fs::read(&path).unwrap().len(), 0, "there before openssl writes");
        #[cfg(unix)]
        assert_eq!(mode(&path), 0o600);
        drop(tmp);
        assert!(!path.exists(), "removed with the attempt");

        // a making that fails half way - no saml directory to write the certificate into, and
        // openssl refused - leaves no key behind under any name
        let broken = scratch("broken");
        std::fs::create_dir_all(&broken).unwrap();
        assert!(make_signer(&broken).is_err(), "no saml directory");
        assert!(openssl(&["genpkey", "-algorithm", "no-such-algorithm", "-out"], &broken.join("x")).is_err());
        let left: Vec<_> = std::fs::read_dir(&broken).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert!(left.iter().all(|n| !n.to_string_lossy().contains("private") && !n.to_string_lossy().ends_with(".pem")), "{left:?}");

        // every name the making can leave under tests/fixtures is one .gitignore names
        let ignore = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/.gitignore")).unwrap();
        for line in ["/tests/fixtures/**/*private*", "/tests/fixtures/**/*_key.pem", "/tests/fixtures/saml/signer_cert.pem",
                     "/tests/fixtures/ec_p256_jwk_x.txt", "/tests/fixtures/ec_p256_jwk_y.txt", "/tests/fixtures/.keys.lock"] {
            assert!(ignore.lines().any(|l| l.trim() == line), "{line} is not ignored");
        }
        for name in [EC_PEM, SIGNER_KEY, ".private-ec-1.tmp", "saml/.private-signer-1.tmp"] {
            assert!(name.contains("private") || name.ends_with("_key.pem"), "{name} would not be ignored");
        }
        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::remove_dir_all(&broken).unwrap();
    }

    /// [review 2026-11-15, the second] the lock is given back when the work panics, one maker
    /// works at a time, what a killed run left is removed by the next - and the fallback directory
    /// is used only when it is this user's alone
    #[test]
    fn the_lock_survives_a_panic_and_a_killed_runs_files_are_swept() {
        let dir = scratch("lock");
        // a panic under the lock: the next ask does not wait for it
        let panicked = std::panic::catch_unwind(|| locked(&dir, || -> io::Result<()> { panic!("the making failed") }));
        assert!(panicked.is_err());
        assert_eq!(locked(&dir, || Ok(7)).unwrap(), 7);

        // one at a time: nobody finds the other inside
        let inside = std::sync::atomic::AtomicUsize::new(0);
        let most = std::sync::atomic::AtomicUsize::new(0);
        std::thread::scope(|s| {
            for _ in 0..4 {
                s.spawn(|| {
                    locked(&dir, || {
                        let now = inside.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                        most.fetch_max(now, std::sync::atomic::Ordering::SeqCst);
                        std::thread::sleep(std::time::Duration::from_millis(40));
                        inside.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                        Ok(())
                    })
                    .unwrap();
                });
            }
        });
        assert_eq!(most.load(std::sync::atomic::Ordering::SeqCst), 1);

        // a run that was killed left a key under its temp name, and a half-written file
        for left in [".private-ec-4194999.tmp", "saml/.private-idp-4194999.tmp", "saml/.making-idp_cert.pem-4194999.tmp"] {
            std::fs::write(dir.join(left), "-----BEGIN PRIVATE KEY-----").unwrap();
        }
        std::fs::write(dir.join("saml/kept.xml"), "a document").unwrap();
        locked(&dir, || Ok(())).unwrap();
        assert_eq!(names(&dir), [".keys.lock", "kept.xml", "saml"], "only the dead run's files are gone");

        // whole or not there
        write_whole(&dir.join("saml/idp_cert.pem"), b"whole").unwrap();
        assert_eq!(std::fs::read(dir.join("saml/idp_cert.pem")).unwrap(), b"whole");
        assert_eq!(names(&dir), [".keys.lock", "idp_cert.pem", "kept.xml", "saml"]);
        // the lock of the first version, a directory, is no obstacle
        std::fs::remove_file(dir.join(LOCK)).unwrap();
        std::fs::create_dir_all(dir.join(LOCK).join("x")).unwrap();
        assert_eq!(locked(&dir, || Ok(1)).unwrap(), 1);
        std::fs::remove_dir_all(&dir).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let own = own_temp_dir().expect("a directory of the user's own");
            assert_eq!(mode(&own), 0o700);
            assert!(own.file_name().unwrap().to_string_lossy().starts_with("signon-test-keys-"));
            // open to others, it is not used: its keys could be anybody's
            std::fs::set_permissions(&own, std::fs::Permissions::from_mode(0o755)).unwrap();
            assert!(own_temp_dir().is_none());
            std::fs::set_permissions(&own, std::fs::Permissions::from_mode(0o700)).unwrap();
            assert_eq!(own_temp_dir().as_deref(), Some(own.as_path()));
        }
    }
}
