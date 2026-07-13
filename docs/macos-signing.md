# macOS: distribuição do `.app`

Público-alvo: **desenvolvedores**. Sem conta paga Apple Developer, então o build
usa **assinatura ad-hoc** (grátis) — o mínimo para o app rodar em Apple Silicon.
Notarização (Developer ID, US$99/ano) é opcional e fica documentada no fim.

## Como está configurado

`src-tauri/tauri.conf.json` → `bundle.macOS.signingIdentity: "-"` faz
`bun run tauri build` assinar o app **e** o sidecar `yellow-vpn-helper` ad-hoc,
com hardened runtime + `entitlements.plist`. Nada de credenciais.

```sh
bun run tauri build
# → target/release/bundle/macos/yellow-vpn.app
# → target/release/bundle/dmg/yellow-vpn_0.1.0_aarch64.dmg
```

## O que o usuário (dev) vê

Ad-hoc **não** passa no Gatekeeper: ao baixar (`.dmg` pela web ganha o atributo
`com.apple.quarantine`), o macOS diz *"não foi possível verificar o
desenvolvedor"* ou *"está danificado"*. Duas saídas — inclua no README de
release:

1. **Botão direito → Abrir** (uma vez): clicar com o botão direito no `.app` →
   *Abrir* → *Abrir* no diálogo. Fura o Gatekeeper para aquele app.

2. **Remover a quarentena** (terminal):
   ```sh
   xattr -dr com.apple.quarantine /Applications/yellow-vpn.app
   ```

Sem uma dessas, em Apple Silicon o app não abre (duplo-clique só mostra o aviso).

## Verificar a assinatura ad-hoc

```sh
A=target/release/bundle/macos/yellow-vpn.app
codesign -dv "$A"                          # Signature=adhoc
codesign --verify --deep --strict "$A"     # sem saída = OK
```

## (Opcional) Notarização com Developer ID

Se um dia tiver conta paga, o mesmo `tauri build` notariza sozinho quando estas
env vars existem — troque também `signingIdentity` de `"-"` para o Developer ID:

```sh
export APPLE_SIGNING_IDENTITY="Developer ID Application: <Nome> (<TEAMID>)"
# API key:
export APPLE_API_ISSUER="<issuer>" APPLE_API_KEY="<key-id>" APPLE_API_KEY_PATH="/…/AuthKey_<id>.p8"
# …ou Apple ID:
export APPLE_ID="voce@exemplo.com" APPLE_PASSWORD="<app-specific>" APPLE_TEAM_ID="<TEAMID>"
bun run tauri build
```

Aí o Gatekeeper aceita sem o usuário fazer nada:
```sh
spctl -a -vvv -t install "$A"       # "accepted / Notarized Developer ID"
xcrun stapler validate "$A"
```

## Notas

- App **não** é sandboxed (o helper precisa de root + utun). As entitlements só
  relaxam o hardened runtime.
- O helper roda como root via `osascript ... with administrator privileges` na
  hora de conectar — pede a senha de admin do mac (equivalente ao UAC).
