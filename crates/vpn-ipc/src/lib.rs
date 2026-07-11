//! Shared IPC message types for the GUI <-> elevated-helper named pipe.
//! Newline-delimited JSON. No async, no engine deps.

use serde::{Deserialize, Serialize};

/// Fixed local named-pipe path (Windows).
pub const PIPE_NAME: &str = r"\\.\pipe\yellow-vpn";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireProtocol {
    AnyConnect,
    Checkpoint,
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
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ClientCommand {
    Connect { config: WireConfig, password: String },
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
        };
        let cmd = ClientCommand::Connect { config: cfg, password: "s3cret".into() };
        let line = serde_json::to_string(&cmd).unwrap();
        let back: ClientCommand = serde_json::from_str(&line).unwrap();
        assert_eq!(cmd, back);
        assert!(!line.contains('\n'), "serialized command must be single-line");
    }

    #[test]
    fn message_round_trips() {
        for m in [
            ClientMessage::State(WireState::Connecting),
            ClientMessage::State(WireState::Reconnecting { delay_secs: 2.5 }),
            ClientMessage::Error { message: "auth failed".into(), permanent: true },
            ClientMessage::Bye,
        ] {
            let line = serde_json::to_string(&m).unwrap();
            let back: ClientMessage = serde_json::from_str(&line).unwrap();
            assert_eq!(m, back);
        }
    }
}
