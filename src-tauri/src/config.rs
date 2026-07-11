//! CLI arg parsing (clap) + optional TOML config with CLI-over-TOML merge.
use std::path::{Path, PathBuf};

use clap::{Parser, ValueEnum};
use serde::Deserialize;

use crate::error::VpnError;

/// Default TLS port when omitted from CLI and TOML (D-04).
pub const DEFAULT_PORT: u16 = 443;

/// Which VPN protocol the client speaks (CP-INT-01). Default preserves v0.1
/// behavior (Cisco AnyConnect / CSTP).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum, Deserialize)]
#[serde(rename_all = "lowercase")]
#[clap(rename_all = "lowercase")]
pub enum Protocol {
    /// Cisco AnyConnect / OpenConnect CSTP (v0.1).
    #[default]
    AnyConnect,
    /// Check Point SNX (CCC + SLIM) (v0.2).
    Checkpoint,
}

/// Command-line arguments (D-01). Every field is optional; required-ness is
/// enforced after merging with the TOML file (D-06).
#[derive(Parser, Debug)]
#[command(name = "vpn-client", version, about = "AnyConnect-compatible SSL VPN client")]
pub struct Args {
    /// VPN server hostname.
    #[arg(short = 'H', long)]
    pub host: Option<String>,

    /// VPN server port (default 443).
    #[arg(short = 'p', long)]
    pub port: Option<u16>,

    /// Authentication username.
    #[arg(short = 'u', long)]
    pub username: Option<String>,

    /// Path to a TOML config file (also accepts --config).
    #[arg(short = 'c', long = "config-file", alias = "config")]
    pub config_file: Option<PathBuf>,

    /// Authentication password (prompted on stdin if omitted).
    #[arg(short = 'P', long)]
    pub password: Option<String>,

    /// Pin the server certificate by its SHA-256 fingerprint (hex, colons
    /// optional, `sha256:` prefix optional). Accepts ONLY the cert with this
    /// fingerprint — use for self-signed / private-CA VPN servers.
    #[arg(long = "servercert", value_name = "SHA256")]
    pub servercert: Option<String>,

    /// DANGER: accept ANY server certificate without verification. Vulnerable to
    /// man-in-the-middle. Debug only — prefer --servercert pinning.
    #[arg(long, action = clap::ArgAction::SetTrue)]
    pub insecure: bool,

    /// VPN protocol: `anyconnect` (Cisco, default) or `checkpoint` (Check Point SNX).
    #[arg(long, value_enum)]
    pub protocol: Option<Protocol>,

    /// Enable DEBUG-level logging.
    #[arg(short = 'v', long, action = clap::ArgAction::SetTrue)]
    pub verbose: bool,
}

/// Raw TOML file schema (D-05). Every section and field is optional in isolation.
#[derive(Debug, Default, Deserialize)]
pub struct FileConfig {
    pub server: Option<ServerSection>,
    pub auth: Option<AuthSection>,
    pub logging: Option<LoggingSection>,
}

#[derive(Debug, Default, Deserialize)]
pub struct ServerSection {
    pub host: Option<String>,
    pub port: Option<u16>,
    /// SHA-256 fingerprint to pin (hex; colons / `sha256:` prefix optional).
    pub cert_sha256: Option<String>,
    /// DANGER: accept any certificate. Prefer cert_sha256.
    pub insecure: Option<bool>,
    /// VPN protocol: `anyconnect` (default) or `checkpoint`.
    pub protocol: Option<Protocol>,
}

#[derive(Debug, Default, Deserialize)]
pub struct AuthSection {
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct LoggingSection {
    pub verbose: Option<bool>,
}

/// Fully-resolved, validated configuration used by the rest of the client.
#[derive(Debug, Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: Option<String>,
    pub verbose: bool,
    /// Pinned server-cert SHA-256 fingerprint (32 bytes), if configured.
    pub cert_sha256: Option<[u8; 32]>,
    /// DANGER: skip all certificate verification.
    pub insecure: bool,
    /// Selected VPN protocol (CP-INT-01); default AnyConnect.
    pub protocol: Protocol,
}

impl Config {
    /// Discover + parse the TOML file, then merge CLI over it and validate.
    pub fn load(args: Args) -> Result<Self, VpnError> {
        let file = load_file_config(args.config_file.as_deref())?;
        Self::merge(args, file)
    }

    /// Merge CLI over TOML (CLI wins — D-07) and run post-merge validation (D-06).
    fn merge(args: Args, file: FileConfig) -> Result<Self, VpnError> {
        let server = file.server.unwrap_or_default();
        let auth = file.auth.unwrap_or_default();
        let logging = file.logging.unwrap_or_default();

        let host = args.host.or(server.host);
        let username = args.username.or(auth.username);
        let password = args.password.or(auth.password);
        let port = args.port.or(server.port).unwrap_or(DEFAULT_PORT); // D-04
        // --verbose is a bool flag (absence == false), so OR with TOML (D-03/D-07).
        let verbose = args.verbose || logging.verbose.unwrap_or(false);
        // Cert trust: CLI --servercert over TOML cert_sha256; --insecure OR TOML insecure.
        let cert_sha256 = match args.servercert.or(server.cert_sha256) {
            Some(s) => Some(parse_sha256_fingerprint(&s)?),
            None => None,
        };
        let insecure = args.insecure || server.insecure.unwrap_or(false);
        // Protocol: CLI over TOML, default AnyConnect (D-07).
        let protocol = args.protocol.or(server.protocol).unwrap_or_default();

        // Collect ALL missing required fields before failing (D-06).
        let mut missing: Vec<&str> = Vec::new();
        if host.is_none() {
            missing.push("host");
        }
        if username.is_none() {
            missing.push("username");
        }
        if !missing.is_empty() {
            return Err(VpnError::Config(format!(
                "missing required configuration: {}. \
                 Provide via CLI (--host/--username) or a config file [server]/[auth].",
                missing.join(", ")
            )));
        }

        Ok(Config {
            host: host.expect("checked above"),
            port,
            username: username.expect("checked above"),
            password,
            verbose,
            cert_sha256,
            insecure,
            protocol,
        })
    }

    /// Return the password, prompting on stdin (no-echo) when absent (D-02).
    /// Invoked before connecting (Phase 3); not called in the Phase 1 exit path.
    pub fn resolve_password(&self) -> Result<String, VpnError> {
        match &self.password {
            Some(p) => Ok(p.clone()),
            None => rpassword::prompt_password("Password: ")
                .map_err(|e| VpnError::Config(format!("failed to read password: {e}"))),
        }
    }
}

/// Parse a SHA-256 fingerprint string into 32 raw bytes. Accepts an optional
/// `sha256:` prefix and optional `:` separators; case-insensitive hex.
/// Example: `sha256:4C:B6:...` or `4cb652...` (64 hex chars).
pub fn parse_sha256_fingerprint(input: &str) -> Result<[u8; 32], VpnError> {
    let cleaned: String = input
        .trim()
        .trim_start_matches("sha256:")
        .trim_start_matches("SHA256:")
        .chars()
        .filter(|c| *c != ':' && !c.is_whitespace())
        .collect();
    if cleaned.len() != 64 || !cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(VpnError::Config(format!(
            "invalid SHA-256 fingerprint '{input}': expected 64 hex characters (32 bytes)"
        )));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&cleaned[i * 2..i * 2 + 2], 16)
            .map_err(|e| VpnError::Config(format!("invalid fingerprint hex: {e}")))?;
    }
    Ok(out)
}

/// Locate and parse the TOML config (D-08 / D-09).
fn load_file_config(explicit: Option<&Path>) -> Result<FileConfig, VpnError> {
    if let Some(path) = explicit {
        // D-08: an explicit path that does not exist is a hard error.
        if !path.exists() {
            return Err(VpnError::Config(format!(
                "config file not found: {}",
                path.display()
            )));
        }
        return parse_toml(path);
    }

    // D-09: auto-discovery in priority order; silent skip if none exist.
    let cwd = PathBuf::from("vpn-client.toml");
    if cwd.exists() {
        return parse_toml(&cwd);
    }
    if let Some(home) = home_dir() {
        let user = home.join(".config").join("vpn-client").join("config.toml");
        if user.exists() {
            return parse_toml(&user);
        }
    }
    Ok(FileConfig::default())
}

fn parse_toml(path: &Path) -> Result<FileConfig, VpnError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| VpnError::Config(format!("cannot read {}: {e}", path.display())))?;
    toml::from_str(&text)
        .map_err(|e| VpnError::Config(format!("invalid TOML in {}: {e}", path.display())))
}

/// Home directory: $HOME (unix) or %USERPROFILE% (windows). No extra crate needed.
fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_args() -> Args {
        Args {
            host: None,
            port: None,
            username: None,
            config_file: None,
            password: None,
            servercert: None,
            insecure: false,
            protocol: None,
            verbose: false,
        }
    }

    #[test]
    fn cli_overrides_toml() {
        let mut a = empty_args();
        a.host = Some("cli-host".into());
        a.username = Some("cli-user".into());
        let file = FileConfig {
            server: Some(ServerSection {
                host: Some("toml-host".into()),
                port: Some(8443),
                ..Default::default()
            }),
            ..Default::default()
        };
        let cfg = Config::merge(a, file).unwrap();
        assert_eq!(cfg.host, "cli-host"); // CLI wins (D-07)
        assert_eq!(cfg.port, 8443); // TOML used when CLI port absent
    }

    #[test]
    fn default_port_when_absent() {
        let mut a = empty_args();
        a.host = Some("h".into());
        a.username = Some("u".into());
        let cfg = Config::merge(a, FileConfig::default()).unwrap();
        assert_eq!(cfg.port, DEFAULT_PORT); // D-04
    }

    #[test]
    fn missing_required_lists_all() {
        let err = Config::merge(empty_args(), FileConfig::default()).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("host"), "message should mention host: {msg}");
        assert!(msg.contains("username"), "message should mention username: {msg}");
    }

    #[test]
    fn resolve_password_precedence() {
        let cfg = Config {
            host: "h".into(),
            port: 443,
            username: "u".into(),
            password: Some("secret".into()),
            verbose: false,
            cert_sha256: None,
            insecure: false,
            protocol: Protocol::AnyConnect,
        };
        // password present => no prompt, returns it directly (D-02).
        assert_eq!(cfg.resolve_password().unwrap(), "secret");
    }

    #[test]
    fn protocol_defaults_to_anyconnect() {
        let mut a = empty_args();
        a.host = Some("h".into());
        a.username = Some("u".into());
        let cfg = Config::merge(a, FileConfig::default()).unwrap();
        assert_eq!(cfg.protocol, Protocol::AnyConnect);
    }

    #[test]
    fn protocol_cli_overrides_toml() {
        let mut a = empty_args();
        a.host = Some("h".into());
        a.username = Some("u".into());
        a.protocol = Some(Protocol::Checkpoint);
        let file = FileConfig {
            server: Some(ServerSection {
                protocol: Some(Protocol::AnyConnect),
                ..Default::default()
            }),
            ..Default::default()
        };
        let cfg = Config::merge(a, file).unwrap();
        assert_eq!(cfg.protocol, Protocol::Checkpoint); // CLI wins
    }

    #[test]
    fn protocol_from_toml_when_cli_absent() {
        let mut a = empty_args();
        a.host = Some("h".into());
        a.username = Some("u".into());
        let file = FileConfig {
            server: Some(ServerSection {
                protocol: Some(Protocol::Checkpoint),
                ..Default::default()
            }),
            ..Default::default()
        };
        let cfg = Config::merge(a, file).unwrap();
        assert_eq!(cfg.protocol, Protocol::Checkpoint);
    }

    #[test]
    fn parse_fingerprint_accepts_colons_and_prefix() {
        let expected = [
            0x4c, 0xb6, 0x52, 0x94, 0x82, 0xe0, 0x85, 0xe0, 0x1c, 0x79, 0x4c, 0x2d, 0x83, 0x20,
            0xcf, 0xf8, 0xbd, 0xcd, 0xc2, 0xb8, 0xea, 0xee, 0x1e, 0xc7, 0x27, 0x39, 0x89, 0x9c,
            0xae, 0x1a, 0x74, 0xa7,
        ];
        let colons = "4C:B6:52:94:82:E0:85:E0:1C:79:4C:2D:83:20:CF:F8:BD:CD:C2:B8:EA:EE:1E:C7:27:39:89:9C:AE:1A:74:A7";
        assert_eq!(parse_sha256_fingerprint(colons).unwrap(), expected);
        let prefixed = format!("sha256:{colons}");
        assert_eq!(parse_sha256_fingerprint(&prefixed).unwrap(), expected);
        let bare = "4cb6529482e085e01c794c2d8320cff8bdcdc2b8eaee1ec72739899cae1a74a7";
        assert_eq!(parse_sha256_fingerprint(bare).unwrap(), expected);
    }

    #[test]
    fn parse_fingerprint_rejects_bad_length() {
        assert!(parse_sha256_fingerprint("abcd").is_err());
        assert!(parse_sha256_fingerprint("xy".repeat(32).as_str()).is_err()); // non-hex
    }

    #[test]
    fn servercert_and_insecure_merge() {
        let mut a = empty_args();
        a.host = Some("h".into());
        a.username = Some("u".into());
        a.insecure = true;
        let cfg = Config::merge(a, FileConfig::default()).unwrap();
        assert!(cfg.insecure);
        assert!(cfg.cert_sha256.is_none());
    }
}
