//! `yellow-vpn` — the command-line front end.
//!
//! Runs the engine in the foreground, in THIS process. There is no helper and no
//! IPC: the CLI is already the privileged process, so it opens the TUN device and
//! installs routes directly. That means it must run as root (Linux/macOS) or
//! elevated (Windows); it says so plainly instead of failing deep inside the
//! routing layer.
//!
//! Ctrl+C / SIGTERM tear the tunnel down through the engine's normal shutdown
//! path, so routes are removed before the TUN interface goes away.
//!
//! Argument parsing is hand-rolled: the workspace deliberately keeps its
//! dependency set small, and the surface here is a dozen flags.

use std::collections::HashMap;
use std::io::{Read, Write};
#[cfg(windows)]
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use vpn_engine::config::{parse_sha256_fingerprint, Config, Protocol};

const USAGE: &str = "\
yellow-vpn — Yellow VPN command-line client

USAGE:
    yellow-vpn connect [PROFILE] [OPTIONS]
    yellow-vpn probe   [PROFILE] [OPTIONS]
    yellow-vpn profiles
    yellow-vpn --help | --version

COMMANDS:
    connect [PROFILE]   Bring up the tunnel and stay in the foreground.
                        PROFILE names a file in the profile directory; any
                        option given on the command line overrides it.
                        Needs root: it creates the TUN device and routes.
    probe [PROFILE]     Authenticate, fetch the config and complete the PPP
                        handshake, then report what the gateway offered and
                        disconnect. Touches no TUN device and no routes, so it
                        needs NO privileges. Use it to tell a credential or
                        gateway problem apart from a routing one.
                        (fortigate and checkpoint; not anyconnect.)
    profiles            List available profile names.

CONNECTION OPTIONS:
    -H, --host HOST         Gateway hostname or IP (required)
    -p, --port PORT         Gateway port [default: 443]
    -u, --user USER         Username (required)
        --protocol PROTO    anyconnect | checkpoint | fortigate [default: anyconnect]
        --realm REALM       FortiGate authentication realm [default: none]

PASSWORD (in order of precedence):
        --password-stdin    Read the password from standard input
        $YELLOW_VPN_PASSWORD
        password = ...      in the profile file
        (otherwise the CLI prompts, with echo disabled)

EXPIRED PASSWORD (check point only):
    If the gateway reports the password as expired, the CLI asks for a new one
    (twice, or $YELLOW_VPN_NEW_PASSWORD) and changes it during login. The old
    password stops working: update any stored copy yourself.

TLS OPTIONS:
        --servercert SHA256 Pin the server certificate by SHA-256 fingerprint.
                            Accepts `sha256:AA:BB:...` or bare hex.
        --insecure          DANGER: disable all certificate verification.

OTHER:
    -v, --verbose           Debug logging (also honours $RUST_LOG)
        --profile-dir DIR   Override the profile directory
    -h, --help              Show this help
    -V, --version           Show the version

PROFILE FILES:
    Linux/macOS: ~/.config/yellow-vpn/profiles/<name>.conf
    Windows:     %APPDATA%\\yellow-vpn\\profiles\\<name>.conf

    Simple `key = value` lines; `#` starts a comment. Recognised keys:
    host, port, username, password, protocol, realm, insecure, servercert.

    A profile containing a password should be mode 0600 — the CLI warns if it
    is readable by anyone else.

EXAMPLES:
    sudo yellow-vpn connect --host vpn.example.com --user alice --protocol fortigate
    YELLOW_VPN_PASSWORD=... sudo -E yellow-vpn connect work
    printf '%s' \"$PASS\" | sudo yellow-vpn connect work --password-stdin
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("yellow-vpn: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<(), String> {
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        print!("{USAGE}");
        return Ok(());
    }
    if args.iter().any(|a| a == "-V" || a == "--version") {
        println!("yellow-vpn {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    match args[0].as_str() {
        "connect" => cmd_connect(&args[1..]),
        "profiles" => cmd_profiles(&args[1..]),
        "probe" => cmd_probe(&args[1..]),
        other => Err(format!("unknown command {other:?}; try --help")),
    }
}

// ---------------------------------------------------------------------------
// Argument + profile parsing
// ---------------------------------------------------------------------------

/// Everything the CLI can be told, from either source. `None` means "not set
/// here", so command-line values can override profile values cleanly.
#[derive(Debug, Default)]
struct Settings {
    host: Option<String>,
    port: Option<u16>,
    username: Option<String>,
    password: Option<String>,
    protocol: Option<Protocol>,
    realm: Option<String>,
    insecure: Option<bool>,
    servercert: Option<String>,
    verbose: bool,
    password_stdin: bool,
    profile_dir: Option<PathBuf>,
}

impl Settings {
    /// Overlay `other` on top of `self`; set values in `other` win.
    fn merge_over(&mut self, other: Settings) {
        macro_rules! take {
            ($($f:ident),*) => { $( if other.$f.is_some() { self.$f = other.$f; } )* };
        }
        take!(host, port, username, password, protocol, realm, insecure, servercert, profile_dir);
        self.verbose |= other.verbose;
        self.password_stdin |= other.password_stdin;
    }
}

fn parse_protocol(s: &str) -> Result<Protocol, String> {
    match s.to_ascii_lowercase().replace(['-', '_'], "").as_str() {
        "anyconnect" | "cisco" | "cstp" => Ok(Protocol::AnyConnect),
        "checkpoint" | "snx" => Ok(Protocol::Checkpoint),
        "fortigate" | "fortinet" | "forticlient" | "forti" => Ok(Protocol::FortiGate),
        other => Err(format!(
            "unknown protocol {other:?}; expected anyconnect, checkpoint, or fortigate"
        )),
    }
}

fn parse_bool(s: &str) -> Result<bool, String> {
    match s.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        other => Err(format!("expected a boolean, got {other:?}")),
    }
}

/// Parse the flags, returning the settings and the optional positional profile.
fn parse_args(args: &[String]) -> Result<(Settings, Option<String>), String> {
    let mut s = Settings::default();
    let mut profile = None;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        // Accept `--flag=value` as well as `--flag value`.
        let (flag, inline) = match a.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f, Some(v.to_string())),
            _ => (a, None),
        };
        let mut value = |name: &str| -> Result<String, String> {
            if let Some(v) = inline.clone() {
                return Ok(v);
            }
            i += 1;
            args.get(i)
                .cloned()
                .ok_or_else(|| format!("{name} needs a value"))
        };
        match flag {
            "-H" | "--host" => s.host = Some(value("--host")?),
            "-p" | "--port" => {
                let v = value("--port")?;
                s.port = Some(v.parse().map_err(|_| format!("invalid port {v:?}"))?);
            }
            "-u" | "--user" | "--username" => s.username = Some(value("--user")?),
            "--protocol" => s.protocol = Some(parse_protocol(&value("--protocol")?)?),
            "--realm" => s.realm = Some(value("--realm")?),
            "--servercert" => s.servercert = Some(value("--servercert")?),
            "--profile-dir" => s.profile_dir = Some(PathBuf::from(value("--profile-dir")?)),
            "--insecure" => s.insecure = Some(true),
            "--password-stdin" => s.password_stdin = true,
            "-v" | "--verbose" => s.verbose = true,
            other if other.starts_with('-') => {
                return Err(format!("unknown option {other:?}; try --help"))
            }
            other => {
                if profile.is_some() {
                    return Err(format!("unexpected extra argument {other:?}"));
                }
                profile = Some(other.to_string());
            }
        }
        i += 1;
    }
    Ok((s, profile))
}

/// Default profile directory for this OS.
fn default_profile_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    let base = std::env::var_os("APPDATA").map(PathBuf::from);
    #[cfg(not(windows))]
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")));
    base.map(|b| b.join("yellow-vpn").join("profiles"))
}

/// Resolve the profile directory, preferring the invoking user's home over
/// root's when running under `sudo` — otherwise `sudo yellow-vpn connect work`
/// would look in `/root/.config` and never find the profile.
fn profile_dir(override_dir: Option<&Path>) -> Option<PathBuf> {
    if let Some(d) = override_dir {
        return Some(d.to_path_buf());
    }
    #[cfg(not(windows))]
    if let Some(user) = std::env::var_os("SUDO_USER") {
        if let Some(home) = home_of(&user.to_string_lossy()) {
            let p = home.join(".config").join("yellow-vpn").join("profiles");
            if p.is_dir() {
                return Some(p);
            }
        }
    }
    default_profile_dir()
}

/// Home directory for a username, read from the passwd database.
#[cfg(not(windows))]
fn home_of(user: &str) -> Option<PathBuf> {
    nix::unistd::User::from_name(user).ok().flatten().map(|u| u.dir)
}

/// Parse a `key = value` profile file. Unknown keys are reported rather than
/// silently ignored, so a typo does not turn into a mysterious connection.
fn parse_profile(text: &str) -> Result<Settings, String> {
    let mut kv: HashMap<String, String> = HashMap::new();
    for (n, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let (k, v) = line
            .split_once('=')
            .ok_or_else(|| format!("line {}: expected `key = value`, got {line:?}", n + 1))?;
        kv.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
    }
    let mut s = Settings::default();
    for (k, v) in kv {
        match k.as_str() {
            "host" | "gateway" => s.host = Some(v),
            "port" => s.port = Some(v.parse().map_err(|_| format!("invalid port {v:?}"))?),
            "username" | "user" => s.username = Some(v),
            "password" => s.password = Some(v),
            "protocol" => s.protocol = Some(parse_protocol(&v)?),
            "realm" => s.realm = Some(v),
            "insecure" => s.insecure = Some(parse_bool(&v)?),
            "servercert" | "cert_sha256" => s.servercert = Some(v),
            other => return Err(format!("unknown profile key {other:?}")),
        }
    }
    Ok(s)
}

fn load_profile(dir: &Path, name: &str) -> Result<Settings, String> {
    if name.contains(['/', '\\']) || name.contains("..") {
        return Err(format!("invalid profile name {name:?}"));
    }
    let path = dir.join(format!("{name}.conf"));
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read profile {}: {e}", path.display()))?;
    warn_if_world_readable(&path);
    parse_profile(&text).map_err(|e| format!("{}: {e}", path.display()))
}

/// A profile file may hold a plaintext password; warn if anyone but the owner
/// can read it.
#[cfg(not(windows))]
fn warn_if_world_readable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(md) = std::fs::metadata(path) {
        let mode = md.permissions().mode() & 0o077;
        if mode != 0 {
            eprintln!(
                "yellow-vpn: warning: {} is readable by other users (mode {:o}); \
                 run: chmod 600 {}",
                path.display(),
                md.permissions().mode() & 0o777,
                path.display()
            );
        }
    }
}

#[cfg(windows)]
fn warn_if_world_readable(_path: &Path) {}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

fn cmd_profiles(args: &[String]) -> Result<(), String> {
    let (s, _) = parse_args(args)?;
    let Some(dir) = profile_dir(s.profile_dir.as_deref()) else {
        return Err("cannot determine the profile directory; pass --profile-dir".into());
    };
    let Ok(entries) = std::fs::read_dir(&dir) else {
        println!("no profiles yet ({} does not exist)", dir.display());
        return Ok(());
    };
    let mut names: Vec<String> = entries
        .flatten()
        .filter_map(|e| {
            let p = e.path();
            (p.extension()?.to_str()? == "conf")
                .then(|| p.file_stem()?.to_str().map(String::from))
                .flatten()
        })
        .collect();
    names.sort();
    if names.is_empty() {
        println!("no profiles in {}", dir.display());
    } else {
        println!("profiles in {}:", dir.display());
        for n in names {
            println!("  {n}");
        }
    }
    Ok(())
}

/// `probe` — everything `connect` does except the parts that need privileges.
///
/// Authenticates, fetches the tunnel config, opens the tunnel and completes the
/// PPP handshake, prints what the gateway said, then hangs up. It never touches
/// the TUN device or the routing table, so it runs as a normal user. This is the
/// fastest way to tell a credential problem from a routing problem, and it is
/// how the FortiGate path is verified against a real gateway.
fn cmd_probe(args: &[String]) -> Result<(), String> {
    let (cli, profile_name) = parse_args(args)?;
    let mut settings = Settings::default();
    if let Some(name) = &profile_name {
        let Some(dir) = profile_dir(cli.profile_dir.as_deref()) else {
            return Err("cannot determine the profile directory; pass --profile-dir".into());
        };
        settings = load_profile(&dir, name)?;
    }
    settings.merge_over(cli);
    init_logging(settings.verbose);

    let host = settings.host.clone().ok_or("--host is required")?;
    let username = settings.username.clone().ok_or("--user is required")?;
    let port = settings.port.unwrap_or(443);
    let realm = settings.realm.clone().unwrap_or_default();
    let protocol = settings.protocol.unwrap_or_default();
    if protocol == Protocol::AnyConnect {
        return Err("probe supports --protocol fortigate and checkpoint only".into());
    }
    let trust = if let Some(s) = settings.servercert.as_deref().filter(|s| !s.trim().is_empty()) {
        vpn_engine::tunnel::CertTrust::Pinned(
            parse_sha256_fingerprint(s).map_err(|e| e.to_string())?,
        )
    } else if settings.insecure.unwrap_or(false) {
        vpn_engine::tunnel::CertTrust::Insecure
    } else {
        vpn_engine::tunnel::CertTrust::Webpki
    };
    let password = resolve_password(&settings, &host, &username)?;

    let rt = tokio::runtime::Runtime::new().map_err(|e| format!("tokio runtime: {e}"))?;
    if protocol == Protocol::Checkpoint {
        return rt.block_on(probe_checkpoint(&host, port, &trust, &username, &password));
    }
    rt.block_on(async {
        use vpn_engine::fortigate::{auth, config as fgcfg, http, session};

        println!("== 1. authenticate ==");
        let mut sess = http::HttpSession::new(&host, port, &trust);
        let cookie = auth::authenticate_on(&mut sess, &username, &password, &realm)
            .await
            .map_err(|e| e.to_string())?;
        println!("   SVPNCOOKIE obtained ({} bytes)", cookie.len());

        println!("== 2. tunnel config ==");
        let cfg = fgcfg::fetch_config_on(&mut sess, &cookie)
            .await
            .map_err(|e| e.to_string())?;
        drop(sess);
        println!("   wire version : {}", cfg.version.as_deref().unwrap_or("?"));
        println!("   methods      : {:?}", cfg.tunnel_methods);
        println!("   assigned addr: {:?}", cfg.address);
        println!("   dns          : {:?}", cfg.dns);
        println!("   idle timeout : {:?}s", cfg.idle_timeout);
        println!("   routes       : {} include, {} exclude",
                 cfg.routes.len(), cfg.exclude_routes.len());
        for (ip, p) in &cfg.routes {
            println!("     - {ip}/{p}");
        }
        for (ip, p) in &cfg.exclude_routes {
            println!("     ! {ip}/{p} (excluded)");
        }

        println!("== 3. tunnel + PPP ==");
        let (stream, ppp, prime) = session::open_tunnel(&host, port, &trust, &cookie)
            .await
            .map_err(|e| e.to_string())?;
        println!("   negotiated addr: {}", ppp.address);
        println!("   peer addr      : {:?}", ppp.peer);
        println!("   dns via IPCP   : {:?}", ppp.dns);
        println!("   MTU (MRU)      : {}", ppp.mtu);
        println!("   early frames   : {} bytes", prime.len());
        drop(stream);

        let params = cfg.to_session_params(Some(&ppp));
        println!("== 4. resulting session ==");
        println!("   address   : {}", params.address);
        println!("   netmask   : {:?}", params.netmask);
        println!("   dns       : {:?}", params.dns);
        println!("   mtu       : {}", params.mtu);
        println!("   keepalive : {:?}s", params.keepalive);
        println!("\nprobe OK — the gateway is reachable and the handshake completes.");
        println!("Run `sudo yellow-vpn connect ...` to bring the tunnel up for real.");
        Ok::<(), String>(())
    })
}

/// The Check Point half of `probe`: CCC UserPass auth on one socket, then the
/// SLIM `client_hello`/`hello_reply` exchange on the separate data socket. Stops
/// before the TUN device and the routing table, so it needs no privileges.
///
/// Note the two things this reports that `connect` only logs: the `tcpt_port` the
/// gateway wants the data socket on, and whether `hello_reply` carried a `:range`
/// block. An empty range means the gateway pushed NO split routes, and `connect`
/// silently falls back to the hardcoded private ranges.
async fn probe_checkpoint(
    host: &str,
    port: u16,
    trust: &vpn_engine::tunnel::CertTrust,
    username: &str,
    password: &str,
) -> Result<(), String> {
    use vpn_engine::checkpoint::{auth as cp_auth, session as cp_session};

    println!("== 1. CCC authenticate ==");
    let first =
        cp_auth::authenticate_checkpoint_with_change(host, port, trust, username, password, None)
            .await;
    let (ccc, changed) = match first {
        Err(vpn_engine::VpnError::PasswordExpired { prompt }) => {
            let new_password = resolve_new_password(&prompt)?;
            cp_auth::authenticate_checkpoint_with_change(
                host,
                port,
                trust,
                username,
                password,
                Some(&new_password),
            )
            .await
            .map_err(|e| e.to_string())?
        }
        other => other.map_err(|e| e.to_string())?,
    };
    if changed {
        println!("   password CHANGED on the gateway — the old one no longer works");
    }
    let cookie = ccc.active_key_deobfuscated().map_err(|e| e.to_string())?;
    println!("   session_id : {:?}", ccc.session_id);
    println!("   active_key : obtained ({} chars, redacted)", cookie.len());
    println!("   tcpt_port  : {}", ccc.tcpt_port);

    println!("== 2. SLIM data tunnel + client_hello ==");
    let mut stream = vpn_engine::tunnel::connect_tls(host, ccc.tcpt_port, trust)
        .await
        .map_err(|e| e.to_string())?;
    let session =
        cp_session::establish_session(&mut stream, &cookie, cp_session::HelloOpts::default())
            .await
            .map_err(|e| e.to_string())?;
    drop(stream);
    println!("   assigned addr : {}/{}", session.address, session.prefix);
    println!("   dns           : {:?}", session.dns);
    println!("   search domains: {:?}", session.search_domains);
    println!("   keepalive     : {}s", session.keepalive_secs);
    println!("   reauth window : {}s", session.auth_timeout_secs);
    println!("   routes        : {}", session.routes.len());
    for (ip, p) in &session.routes {
        println!("     - {ip}/{p}");
    }
    if session.routes.is_empty() {
        println!(
            "   ! the gateway pushed NO :range block, so `connect` will fall back to the\n\
             \x20    hardcoded private ranges (10.0.0.0/8, 172.16.0.0/12)."
        );
    }

    let params = session.to_session_params();
    println!("== 3. resulting session ==");
    println!("   address   : {}", params.address);
    println!("   netmask   : {:?}", params.netmask);
    println!("   dns       : {:?}", params.dns);
    println!("   mtu       : {}", params.mtu);
    println!("   keepalive : {:?}s", params.keepalive);

    // Release the session. A probe that leaked one would burn an Office Mode
    // address per run, which is exactly the bug this command exists to surface.
    println!("== 4. sign out ==");
    match cp_auth::signout_checkpoint(host, port, trust, &ccc.session_id).await {
        Ok(()) => println!("   CCC session released"),
        Err(e) => println!("   ! signout failed: {e}"),
    }

    println!("\nprobe OK — the gateway is reachable and the handshake completes.");
    println!("Run `sudo yellow-vpn connect ...` to bring the tunnel up for real.");
    Ok(())
}

fn cmd_connect(args: &[String]) -> Result<(), String> {
    let (cli, profile_name) = parse_args(args)?;

    // Profile first, command line on top.
    let mut settings = Settings::default();
    if let Some(name) = &profile_name {
        let Some(dir) = profile_dir(cli.profile_dir.as_deref()) else {
            return Err("cannot determine the profile directory; pass --profile-dir".into());
        };
        settings = load_profile(&dir, name)?;
    }
    settings.merge_over(cli);

    init_logging(settings.verbose);

    let host = settings.host.clone().ok_or("--host is required")?;
    let username = settings.username.clone().ok_or("--user is required")?;
    let port = settings.port.unwrap_or(443);
    let protocol = settings.protocol.unwrap_or_default();
    let insecure = settings.insecure.unwrap_or(false);

    let cert_sha256 = match settings.servercert.as_deref() {
        Some(s) if !s.trim().is_empty() => Some(parse_sha256_fingerprint(s).map_err(|e| e.to_string())?),
        _ => None,
    };
    if insecure && cert_sha256.is_none() {
        eprintln!(
            "yellow-vpn: warning: --insecure disables certificate verification; \
             the connection can be intercepted. Prefer --servercert <sha256>."
        );
    }

    let password = resolve_password(&settings, &host, &username)?;

    require_privileges()?;

    let mut config = Config {
        host,
        port,
        username,
        password: None, // passed separately; never stored in the config struct
        verbose: settings.verbose,
        cert_sha256,
        insecure,
        protocol,
        realm: settings.realm.unwrap_or_default(),
        new_password: None,
    };

    eprintln!(
        "yellow-vpn: connecting to {}:{} as {} ({})",
        config.host,
        config.port,
        config.username,
        protocol_name(config.protocol)
    );

    let rt = tokio::runtime::Runtime::new().map_err(|e| format!("tokio runtime: {e}"))?;
    match rt.block_on(vpn_engine::run_client(&config, &password)) {
        // The gateway wants a new password before it will log us in: ask for one and
        // go round once more. The engine rotates it during login and uses it for any
        // later reconnect itself.
        Err(vpn_engine::VpnError::PasswordExpired { prompt }) => {
            config.new_password = Some(resolve_new_password(&prompt)?);
            rt.block_on(vpn_engine::run_client(&config, &password))
                .map_err(|e| e.to_string())
        }
        other => other.map_err(|e| e.to_string()),
    }
}

fn protocol_name(p: Protocol) -> &'static str {
    match p {
        Protocol::AnyConnect => "AnyConnect",
        Protocol::Checkpoint => "Check Point SNX",
        Protocol::FortiGate => "FortiGate SSL VPN",
    }
}

fn init_logging(verbose: bool) {
    let default = if verbose { "vpn_engine=debug,info" } else { "info" };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

/// The CLI opens the TUN device and edits the routing table itself, so it needs
/// privileges. Checking up front turns a confusing failure deep in the routing
/// layer into one actionable line.
///
/// Root is not the only way in: on Linux `CAP_NET_ADMIN` alone is enough, so a
/// binary installed with `setcap cap_net_admin+ep` runs as an ordinary user. We
/// accept that too rather than insisting on uid 0.
fn require_privileges() -> Result<(), String> {
    #[cfg(not(windows))]
    {
        if nix::unistd::Uid::effective().is_root() {
            return Ok(());
        }
        if has_cap_net_admin() {
            return Ok(());
        }
        return Err(HELP_PRIVILEGES.into());
    }
    #[cfg(windows)]
    Ok(())
}

#[cfg(target_os = "linux")]
const HELP_PRIVILEGES: &str = "\
needs CAP_NET_ADMIN — the CLI creates the TUN device and installs routes itself.

Either run it with sudo (keep -E so $YELLOW_VPN_PASSWORD survives):
    sudo -E yellow-vpn connect ...

or grant the capability once so no sudo is needed afterwards:
    sudo setcap cap_net_admin+ep $(command -v yellow-vpn)";

#[cfg(all(unix, not(target_os = "linux")))]
const HELP_PRIVILEGES: &str = "\
must run as root — the CLI creates the TUN device and installs routes itself.
Try: sudo -E yellow-vpn connect ...";

/// Whether this process holds `CAP_NET_ADMIN` in its effective set.
///
/// Read from `/proc/self/status` rather than `capget(2)`: it needs no extra
/// dependency and no unsafe code. A missing or unparsable file just means "no",
/// which degrades to the sudo path.
#[cfg(target_os = "linux")]
fn has_cap_net_admin() -> bool {
    const CAP_NET_ADMIN: u32 = 12;
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return false;
    };
    status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
        .is_some_and(|caps| caps & (1 << CAP_NET_ADMIN) != 0)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn has_cap_net_admin() -> bool {
    false
}

// ---------------------------------------------------------------------------
// Password acquisition
// ---------------------------------------------------------------------------

fn resolve_password(s: &Settings, host: &str, user: &str) -> Result<String, String> {
    if s.password_stdin {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| format!("reading the password from stdin: {e}"))?;
        let p = buf.trim_end_matches(['\r', '\n']).to_string();
        if p.is_empty() {
            return Err("--password-stdin was given but stdin was empty".into());
        }
        return Ok(p);
    }
    // An env var beats the profile file: it lets a profile stay password-free.
    if let Ok(p) = std::env::var("YELLOW_VPN_PASSWORD") {
        if !p.is_empty() {
            return Ok(p);
        }
    }
    if let Some(p) = s.password.clone() {
        if !p.is_empty() {
            return Ok(p);
        }
    }
    prompt_password(&format!("Password for {user}@{host}: "))
}

/// Get a replacement password after the gateway reported the current one as
/// expired: `$YELLOW_VPN_NEW_PASSWORD`, else two prompts that must agree.
///
/// Rotating changes the password on the gateway, so say so before asking — the CLI
/// cannot rewrite a stored copy (profile file, env var) and the old one stops working.
fn resolve_new_password(gateway_prompt: &str) -> Result<String, String> {
    // The text comes from the gateway; drop control characters before echoing it.
    let shown: String = gateway_prompt.chars().filter(|c| !c.is_control()).collect();
    eprintln!("yellow-vpn: the gateway says: {shown}");
    eprintln!(
        "yellow-vpn: this will CHANGE your password on the gateway. Update any stored \
         copy (profile file, $YELLOW_VPN_PASSWORD) afterwards."
    );
    if let Ok(p) = std::env::var("YELLOW_VPN_NEW_PASSWORD") {
        if !p.is_empty() {
            return Ok(p);
        }
    }
    let first = prompt_password("New password: ")?;
    let second = prompt_password("Retype new password: ")?;
    if first != second {
        return Err("the two new passwords do not match".into());
    }
    Ok(first)
}

/// Prompt on the terminal with echo disabled.
#[cfg(not(windows))]
fn prompt_password(prompt: &str) -> Result<String, String> {
    use nix::sys::termios::{tcgetattr, tcsetattr, LocalFlags, SetArg};

    let mut tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|e| {
            format!(
                "no password available and no terminal to prompt on ({e}). \
                 Set $YELLOW_VPN_PASSWORD or use --password-stdin."
            )
        })?;

    let saved = tcgetattr(&tty).map_err(|e| format!("tcgetattr: {e}"))?;
    let mut quiet = saved.clone();
    quiet.local_flags.remove(LocalFlags::ECHO);
    tcsetattr(&tty, SetArg::TCSAFLUSH, &quiet).map_err(|e| format!("tcsetattr: {e}"))?;

    write!(tty, "{prompt}").ok();
    tty.flush().ok();

    // Read one line byte by byte; a BufReader would swallow buffered input that
    // belongs to whatever runs after us.
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    let read = loop {
        match std::io::Read::read(&mut tty, &mut byte) {
            Ok(0) => break Ok(()),
            Ok(_) if byte[0] == b'\n' => break Ok(()),
            Ok(_) if byte[0] == b'\r' => continue,
            Ok(_) => line.push(byte[0]),
            Err(e) => break Err(format!("reading password: {e}")),
        }
    };

    // Restore the terminal on every path, including the error one.
    let _ = tcsetattr(&tty, SetArg::TCSAFLUSH, &saved);
    writeln!(tty).ok();
    read?;

    let p = String::from_utf8(line).map_err(|_| "password is not valid UTF-8".to_string())?;
    if p.is_empty() {
        return Err("empty password".into());
    }
    Ok(p)
}

#[cfg(windows)]
fn prompt_password(prompt: &str) -> Result<String, String> {
    // No termios here; the console-mode dance is not worth a dependency for the
    // Windows CLI, which is the least-used path. Be explicit that it echoes.
    if !std::io::stdin().is_terminal() {
        return Err(
            "no password available; set %YELLOW_VPN_PASSWORD% or use --password-stdin".into(),
        );
    }
    eprint!("{prompt}(warning: the password will be visible) ");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| format!("reading password: {e}"))?;
    let p = line.trim_end_matches(['\r', '\n']).to_string();
    if p.is_empty() {
        return Err("empty password".into());
    }
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn parses_flags_and_positional_profile() {
        let (s, p) = parse_args(&args(&[
            "work", "--host", "vpn.example.com", "-p", "8443", "-u", "alice",
            "--protocol", "fortigate", "--insecure", "-v",
        ]))
        .unwrap();
        assert_eq!(p.as_deref(), Some("work"));
        assert_eq!(s.host.as_deref(), Some("vpn.example.com"));
        assert_eq!(s.port, Some(8443));
        assert_eq!(s.username.as_deref(), Some("alice"));
        assert_eq!(s.protocol, Some(Protocol::FortiGate));
        assert_eq!(s.insecure, Some(true));
        assert!(s.verbose);
    }

    #[test]
    fn accepts_equals_form() {
        let (s, _) = parse_args(&args(&["--host=h", "--port=443", "--protocol=checkpoint"])).unwrap();
        assert_eq!(s.host.as_deref(), Some("h"));
        assert_eq!(s.port, Some(443));
        assert_eq!(s.protocol, Some(Protocol::Checkpoint));
    }

    #[test]
    fn rejects_unknown_option_and_missing_value() {
        assert!(parse_args(&args(&["--nope"])).is_err());
        assert!(parse_args(&args(&["--host"])).is_err());
        assert!(parse_args(&args(&["a", "b"])).is_err());
    }

    #[test]
    fn protocol_aliases_resolve() {
        for a in ["fortigate", "FortiGate", "forti", "fortinet", "forti-client"] {
            assert_eq!(parse_protocol(a).unwrap(), Protocol::FortiGate, "{a}");
        }
        assert_eq!(parse_protocol("snx").unwrap(), Protocol::Checkpoint);
        assert_eq!(parse_protocol("cisco").unwrap(), Protocol::AnyConnect);
        assert!(parse_protocol("openvpn").is_err());
    }

    #[test]
    fn profile_parses_and_ignores_comments() {
        let s = parse_profile(
            "# gateway\n\
             host = vpn.example.com\n\
             port = 443\n\
             username = alice\n\
             protocol = fortigate   # inline comment\n\
             insecure = yes\n\
             \n",
        )
        .unwrap();
        assert_eq!(s.host.as_deref(), Some("vpn.example.com"));
        assert_eq!(s.username.as_deref(), Some("alice"));
        assert_eq!(s.protocol, Some(Protocol::FortiGate));
        assert_eq!(s.insecure, Some(true));
    }

    #[test]
    fn profile_rejects_unknown_key_and_bad_line() {
        assert!(parse_profile("hsot = x").is_err(), "a typo must not be silently ignored");
        assert!(parse_profile("just-a-line").is_err());
    }

    #[test]
    fn command_line_overrides_profile() {
        let mut base = parse_profile("host = from-profile\nusername = alice\nport = 443").unwrap();
        let (cli, _) = parse_args(&args(&["--host", "from-cli"])).unwrap();
        base.merge_over(cli);
        assert_eq!(base.host.as_deref(), Some("from-cli"));
        assert_eq!(base.username.as_deref(), Some("alice"), "unset flags keep the profile value");
        assert_eq!(base.port, Some(443));
    }

    #[test]
    fn profile_name_cannot_escape_its_directory() {
        let dir = std::env::temp_dir();
        assert!(load_profile(&dir, "../../etc/passwd").is_err());
        assert!(load_profile(&dir, "a/b").is_err());
    }

    #[test]
    fn bools_accept_common_spellings() {
        for t in ["1", "true", "yes", "on", "YES"] {
            assert!(parse_bool(t).unwrap(), "{t}");
        }
        for f in ["0", "false", "no", "off"] {
            assert!(!parse_bool(f).unwrap(), "{f}");
        }
        assert!(parse_bool("maybe").is_err());
    }
}
