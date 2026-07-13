# Tauri + React + Typescript

This template should help get you started developing with Tauri, React and Typescript in Vite.

## Recommended IDE Setup

- [VS Code](https://code.visualstudio.com/) + [Tauri](https://marketplace.visualstudio.com/items?itemName=tauri-apps.tauri-vscode) + [rust-analyzer](https://marketplace.visualstudio.com/items?itemName=rust-lang.rust-analyzer)

## Linux privileged helper

The VPN engine runs in an elevated helper (`yellow-vpn-helper`, root). The GUI
launches it on connect:

- **Windows** — UAC prompt.
- **macOS** — native authorization dialog.
- **Linux** — `pkexec` (polkit) graphical prompt.

On a normal desktop (GNOME/KDE) this works out of the box; just make sure
`polkit` / `pkexec` is installed:

- Debian/Ubuntu: `sudo apt install policykit-1` (or `pkexec` on newer releases)
- Fedora/RHEL: `sudo dnf install polkit`
- Arch: `sudo pacman -S polkit`

### Running under WSL2

WSL2 has no graphical polkit agent and usually no `systemd-logind` session, so
`pkexec` falls back to a terminal password prompt and often fails with
`No session for cookie`. Two dev workarounds:

**A. Passwordless pkexec for the helper (recommended).** Add a polkit rule that
skips auth for *your user* running *your* built helper. Returning `YES` also
avoids the missing-session problem. Replace `YOUR_USER` and the path with yours:

```bash
sudo tee /etc/polkit-1/rules.d/49-yellowvpn-dev.rules >/dev/null <<'EOF'
polkit.addRule(function(action, subject) {
    if (action.id == "org.freedesktop.policykit.exec" &&
        subject.user == "YOUR_USER" &&
        action.lookup("program") ==
            "/absolute/path/to/YellowVPN/target/debug/yellow-vpn-helper") {
        return polkit.Result.YES;
    }
});
EOF
```

polkit hot-reloads `rules.d`, so no restart is needed. **Dev only** — remove
before shipping: `sudo rm /etc/polkit-1/rules.d/49-yellowvpn-dev.rules`.

**B. Start the helper manually.** The GUI connects to an existing helper socket
before trying to spawn one, so you can pre-start it (pass your uid, which locks
the socket to you):

```bash
sudo ./target/debug/yellow-vpn-helper $(id -u)
```

Note the helper is one-shot: it serves a single connection then exits, so
restart it for each connect.

Full VPN testing under WSL2 is unreliable anyway (no TUN device by default, no
real desktop) — a real Linux desktop is the intended target.
