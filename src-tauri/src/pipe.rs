//! Client to the elevated helper + privileged spawn of that helper.
//!
//! Transport is per-OS: a Windows named pipe (UAC-elevated helper) or a Unix
//! domain socket (root helper, elevated via `osascript` on macOS). The `Client`
//! type and `connect_with_spawn` present the same surface to the GUI on both.
use std::io;
use std::path::PathBuf;
#[cfg(any(windows, unix))]
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
#[cfg(windows)]
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};
#[cfg(unix)]
use tokio::net::UnixStream;
use vpn_ipc::ClientCommand;
#[cfg(windows)]
use vpn_ipc::PIPE_NAME;
#[cfg(unix)]
use vpn_ipc::SOCKET_PATH;

/// The connected transport to the helper.
#[cfg(windows)]
pub type Client = NamedPipeClient;
#[cfg(unix)]
pub type Client = UnixStream;

/// Path to the bundled helper binary (next to the GUI executable).
fn helper_path() -> io::Result<PathBuf> {
    let exe = std::env::current_exe()?;
    let dir = exe.parent().ok_or_else(|| io::Error::other("no exe dir"))?;
    #[cfg(windows)]
    let name = "yellow-vpn-helper.exe";
    #[cfg(unix)]
    let name = "yellow-vpn-helper";
    Ok(dir.join(name))
}

/// Launch the helper elevated (UAC). Returns once ShellExecute has been issued;
/// the caller then polls the pipe until the helper has created it.
#[cfg(windows)]
pub fn spawn_helper_elevated() -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

    let path = helper_path()?;
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    let verb: Vec<u16> = "runas".encode_utf16().chain(std::iter::once(0)).collect();

    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            wide.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_HIDE,
        )
    };
    // ShellExecuteW returns a value > 32 on success.
    if (result as isize) <= 32 {
        return Err(io::Error::other("elevation cancelled or failed (UAC)"));
    }
    Ok(())
}

/// Connect to the helper pipe, spawning the elevated helper first if it is absent.
/// Retries the pipe connection for a few seconds to cover UAC + helper startup.
#[cfg(windows)]
pub async fn connect_with_spawn() -> io::Result<Client> {
    // Try an existing helper first.
    if let Ok(c) = ClientOptions::new().open(PIPE_NAME) {
        return Ok(c);
    }
    spawn_helper_elevated()?;
    // Poll for up to ~15s while the user clicks through UAC.
    for _ in 0..150 {
        match ClientOptions::new().open(PIPE_NAME) {
            Ok(c) => return Ok(c),
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    Err(io::Error::other("helper did not come up (pipe never appeared)"))
}

/// Launch the helper as root via the native macOS authorization dialog
/// (`osascript ... with administrator privileges`, the mac equivalent of UAC).
/// The helper is backgrounded inside the elevated shell so this returns as soon
/// as the user completes the prompt; the caller then polls the socket.
#[cfg(target_os = "macos")]
pub fn spawn_helper_elevated() -> io::Result<()> {
    let path = helper_path()?;
    // The path is interpolated into a shell command inside an AppleScript
    // string that runs as ROOT. Characters that could escape either quoting
    // layer (shell single quotes; AppleScript's `"`/`\`) must never reach it,
    // and control characters could confuse the elevated shell. The bundled
    // install path never contains these, so reject rather than escape.
    let path_str = path
        .to_str()
        .ok_or_else(|| io::Error::other("helper path is not valid UTF-8"))?;
    if path_str.contains(['\'', '"', '\\', '`', '$']) || path_str.chars().any(|c| c.is_control()) {
        return Err(io::Error::other(
            "helper path contains characters unsafe for privileged execution",
        ));
    }
    // Pass our (unprivileged) uid so the root helper can lock the control socket
    // to exactly this user (chown + mode 0600), the mac equivalent of the
    // restricted-DACL pipe on Windows.
    let uid = unsafe { libc::getuid() };
    // Single-quote the path for the shell (handles spaces); AppleScript's own
    // string uses double quotes, so single quotes nest cleanly.
    let shell_cmd = format!("'{path_str}' {uid} >/dev/null 2>&1 &");
    let script =
        format!("do shell script \"{shell_cmd}\" with administrator privileges");

    let status = std::process::Command::new("osascript")
        .arg("-e")
        .arg(script)
        .status()?;
    if !status.success() {
        return Err(io::Error::other("elevation cancelled or failed"));
    }
    Ok(())
}

#[cfg(all(unix, not(target_os = "macos")))]
pub fn spawn_helper_elevated() -> io::Result<()> {
    // Linux GUI elevation (pkexec/sudo) is not wired up yet.
    Err(io::Error::other(
        "run the helper manually as root: sudo yellow-vpn-helper",
    ))
}

/// Connect to the helper socket, spawning the elevated helper first if it is
/// absent. Retries for a few seconds to cover the auth prompt + helper startup.
#[cfg(unix)]
pub async fn connect_with_spawn() -> io::Result<Client> {
    // Try an existing helper first.
    if let Ok(c) = UnixStream::connect(SOCKET_PATH).await {
        return Ok(c);
    }
    spawn_helper_elevated()?;
    // Poll for up to ~15s while the user completes the auth prompt.
    for _ in 0..150 {
        match UnixStream::connect(SOCKET_PATH).await {
            Ok(c) => return Ok(c),
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    Err(io::Error::other("helper did not come up (socket never appeared)"))
}

/// Send one command as a JSON line.
pub async fn send_command(
    writer: &mut tokio::io::WriteHalf<Client>,
    cmd: &ClientCommand,
) -> io::Result<()> {
    let mut line = serde_json::to_string(cmd).map_err(io::Error::other)?;
    line.push('\n');
    writer.write_all(line.as_bytes()).await?;
    writer.flush().await
}

/// Split a connected pipe into a writer and a line-reader.
pub fn split(
    client: Client,
) -> (
    tokio::io::WriteHalf<Client>,
    tokio::io::Lines<BufReader<tokio::io::ReadHalf<Client>>>,
) {
    let (r, w) = tokio::io::split(client);
    (w, BufReader::new(r).lines())
}
