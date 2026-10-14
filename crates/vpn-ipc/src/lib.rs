//! Shared IPC message types for the GUI <-> elevated-helper named pipe.
//! Newline-delimited JSON. No async, no engine deps.

use serde::{Deserialize, Serialize};

/// Fixed local named-pipe path (Windows).
pub const PIPE_NAME: &str = r"\\.\pipe\yellow-vpn";

/// Directory that holds the Unix-domain control socket (macOS/Linux). The
/// elevated (root) helper creates it mode 0711 (traverse-only for non-root) so
/// no other user can plant files/symlinks next to the socket — unlike `/tmp`.
#[cfg(unix)]
pub const SOCKET_DIR: &str = "/var/run/yellow-vpn";

/// Fixed local Unix-domain-socket path (macOS/Linux). The root helper binds it,
/// then chowns it to the interactive user with mode 0600 so ONLY that user (and
/// root) can connect — the socket is not world-accessible.
#[cfg(unix)]
pub const SOCKET_PATH: &str = "/var/run/yellow-vpn/helper.sock";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireProtocol {
    AnyConnect,
    Checkpoint,
    FortiGate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub protocol: WireProtocol,
    pub cert_sha256: Option<String>,
    pub insecure: bool,
    pub verbose: bool,
    /// FortiGate authentication realm; `None`/empty means the default realm.
    /// `serde(default)` so an older GUI that omits the field still talks to a
    /// newer helper instead of failing to deserialize the Connect command.
    #[serde(default)]
    pub realm: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ClientCommand {
    Connect {
        config: WireConfig,
        password: String,
        /// Replacement password to submit if the gateway reports `password` as
        /// expired. `serde(default)` so an older GUI still talks to this helper.
        #[serde(default)]
        new_password: Option<String>,
    },
    Disconnect,
    Shutdown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum WireState {
    Connecting,
    Established,
    Reconnecting { delay_secs: f64 },
    Disconnected,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ClientMessage {
    State(WireState),
    Error { message: String, permanent: bool },
    /// The gateway demands a new password; the tunnel is down until the GUI
    /// reconnects with `new_password` set. `prompt` is the gateway's own text.
    PasswordExpired { prompt: String },
    /// The gateway accepted the `new_password` from the last Connect; the GUI
    /// should store it as the profile's password.
    PasswordChanged,
    Bye,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_round_trips() {
        let cfg = WireConfig {
            host: "vpn.example.com".into(),
            port: 443,
            username: "alice".into(),
            protocol: WireProtocol::Checkpoint,
            cert_sha256: Some("aa:bb".into()),
            insecure: false,
            verbose: true,
            realm: Some("corp".into()),
        };
        let cmd = ClientCommand::Connect {
            config: cfg,
            password: "s3cret".into(),
            new_password: Some("n3w".into()),
        };
        let line = serde_json::to_string(&cmd).unwrap();
        let back: ClientCommand = serde_json::from_str(&line).unwrap();
        assert_eq!(cmd, back);
        assert!(!line.contains('\n'), "serialized command must be single-line");
    }

    #[test]
    fn connect_without_new_password_still_deserializes() {
        let line = r#"{"Connect":{"config":{"host":"h","port":443,"username":"u","protocol":"Checkpoint","cert_sha256":null,"insecure":false,"verbose":false},"password":"p"}}"#;
        match serde_json::from_str::<ClientCommand>(line).unwrap() {
            ClientCommand::Connect { new_password, .. } => assert_eq!(new_password, None),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn message_round_trips() {
        for m in [
            ClientMessage::State(WireState::Connecting),
            ClientMessage::State(WireState::Reconnecting { delay_secs: 2.5 }),
            ClientMessage::Error { message: "auth failed".into(), permanent: true },
            ClientMessage::PasswordExpired { prompt: "Enter new password".into() },
            ClientMessage::PasswordChanged,
            ClientMessage::Bye,
        ] {
            let line = serde_json::to_string(&m).unwrap();
            let back: ClientMessage = serde_json::from_str(&line).unwrap();
            assert_eq!(m, back);
        }
    }
}
