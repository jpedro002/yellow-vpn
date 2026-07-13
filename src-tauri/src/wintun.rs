//! First-run acquisition of `wintun.dll`. The driver DLL is NOT bundled (keeps
//! the app small); on Windows it is downloaded once from the official
//! wintun.net release and written next to the executable (where both the GUI
//! and the elevated helper look for it). Progress is streamed to the frontend
//! via `wintun://progress` events so the setup screen can show a bar.

#[cfg(windows)]
use serde::Serialize;

/// Official Wintun release archive (a ZIP containing `wintun/bin/<arch>/wintun.dll`).
#[cfg(windows)]
const WINTUN_URL: &str = "https://www.wintun.net/builds/wintun-0.14.1.zip";

/// SHA-256 of the pinned release archive, as published on https://www.wintun.net.
/// The DLL is loaded into the *elevated* helper, so the download must be
/// integrity-checked, not just fetched over TLS.
#[cfg(windows)]
const WINTUN_ZIP_SHA256: &str = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51";

#[cfg(windows)]
#[derive(Clone, Serialize)]
pub struct Progress {
    /// One of: "download", "extract".
    pub stage: &'static str,
    pub downloaded: u64,
    pub total: u64,
}

/// Ensure `wintun.dll` is present next to the executable.
///
/// Returns `true` if it was already there (no work), `false` if it was just
/// downloaded. On non-Windows targets this is a no-op returning `true`.
#[cfg(windows)]
pub async fn ensure(app: &tauri::AppHandle) -> Result<bool, String> {
    use tauri::Emitter;

    let dir = std::env::current_exe()
        .map_err(|e| format!("cannot locate executable: {e}"))?
        .parent()
        .ok_or_else(|| "executable has no parent directory".to_string())?
        .to_path_buf();
    let target = dir.join("wintun.dll");
    if target.exists() {
        return Ok(true);
    }

    // Pick the DLL matching this build's architecture.
    let arch = if cfg!(target_arch = "x86_64") {
        "amd64"
    } else if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "x86"
    };
    let entry = format!("wintun/bin/{arch}/wintun.dll");

    // Stream the archive, reporting progress.
    let client = reqwest::Client::builder()
        .build()
        .map_err(|e| e.to_string())?;
    let mut resp = client
        .get(WINTUN_URL)
        .send()
        .await
        .map_err(|e| format!("download failed: {e}"))?
        .error_for_status()
        .map_err(|e| format!("download failed: {e}"))?;

    let total = resp.content_length().unwrap_or(0);
    let mut downloaded: u64 = 0;
    let mut buf: Vec<u8> = Vec::with_capacity(total as usize);
    let _ = app.emit("wintun://progress", Progress { stage: "download", downloaded: 0, total });

    // Emit progress at most every 256 KiB (plus a final event below) so a fast
    // download doesn't flood the webview event bus with thousands of events.
    const EMIT_STEP: u64 = 256 * 1024;
    let mut last_emitted: u64 = 0;
    while let Some(chunk) = resp.chunk().await.map_err(|e| format!("download failed: {e}"))? {
        downloaded += chunk.len() as u64;
        buf.extend_from_slice(&chunk);
        if downloaded - last_emitted >= EMIT_STEP {
            last_emitted = downloaded;
            let _ = app.emit("wintun://progress", Progress { stage: "download", downloaded, total });
        }
    }
    let _ = app.emit("wintun://progress", Progress { stage: "download", downloaded, total });

    // Integrity check: the archive must match the pinned release hash before
    // anything is extracted or written to disk.
    {
        use sha2::{Digest, Sha256};
        let got = format!("{:x}", Sha256::digest(&buf));
        if got != WINTUN_ZIP_SHA256 {
            return Err(format!(
                "wintun archive integrity check failed (sha256 {got}, expected {WINTUN_ZIP_SHA256}) — refusing to install"
            ));
        }
    }

    // Extract the arch-matched DLL from the ZIP (in memory) and write it out.
    let _ = app.emit("wintun://progress", Progress { stage: "extract", downloaded, total });
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(buf))
        .map_err(|e| format!("invalid archive: {e}"))?;
    let mut file = archive
        .by_name(&entry)
        .map_err(|_| format!("wintun.dll for '{arch}' not found in archive"))?;
    let mut dll = Vec::with_capacity(file.size() as usize);
    std::io::Read::read_to_end(&mut file, &mut dll).map_err(|e| e.to_string())?;
    std::fs::write(&target, &dll)
        .map_err(|e| format!("cannot write {}: {e}", target.display()))?;

    Ok(false)
}

#[cfg(not(windows))]
pub async fn ensure(_app: &tauri::AppHandle) -> Result<bool, String> {
    Ok(true)
}
