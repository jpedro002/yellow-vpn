# Check Point password rotation — live validation and review

Status: implemented, **not validated against a real gateway**. Run this when a test
account with an expired password is available.

## What exists

Expired-password rotation over CCC: `authenticate_checkpoint_with_change`
(`crates/vpn-engine/src/checkpoint/auth.rs`) → `VpnError::PasswordExpired` →
`ClientEvent::PasswordExpired` / `PasswordChanged` → `vpn-ipc` messages → GUI
`PasswordChangeDialog`; Android notices via `vpn_notice`; CLI prompts in
`probe` / `connect`. Only unit tests have run.

## Unverified assumptions (the point of this validation)

Each came from snx-rs / an earlier session's notes, not from the reference client
(Endpoint Connect speaks IKE, not CCC).

1. Challenge reply is `return_code 600` + `auth_state (new_challenge)`, with
   `prompt` / `prompt_id` obfuscated by the SNX cipher. Parser looks in
   `ResponseData` first, then `ResponseHeader`.
2. Follow-up request type is `MultiChallange` (misspelled); `MultiChallenge` → 502.
3. Request carries `session_id` in the header and `auth_session_id` + `user_input`
   in the data; header `id` increments per round.
4. Both rounds (new password, retype) take the SAME new password.
   **Doubt:** in the reference's `trac.log.3` (20 Aug 11:26) the IKE replies were 22
   bytes for the current password, 22 for the new one and 23 for the retype. Not
   explained; may just be the cipher/obfuscation, may mean the retype differs.
5. After the retype round the gateway returns 600 + `active_key`, and the old
   password stops working.
6. Signing out the pending challenge session is harmless (best-effort).

## Before the test

- [ ] Account approved for a real password change (rotation changes it for real).
- [ ] Know the gateway's password policy (length, history, complexity) so a policy
      rejection is not mistaken for a protocol bug.
- [ ] Have `RUST_LOG=vpn_engine=debug` ready. Do NOT paste logs publicly; they hold
      obfuscated credentials.
- [ ] Optional: re-read `trac.log.3` around the retype in the reference app
      (`C:\Program Files (x86)\CheckPoint\Endpoint Connect`) for what follows it
      and for the 22/22/23 byte question.

## Test steps

1. **No new password.** `yellow-vpn probe <profile>` (non-interactive, no
   `$YELLOW_VPN_NEW_PASSWORD`) must stop with the password-expired prompt and must
   NOT change the password. Confirms assumption 1 and the `PasswordExpired` path.
2. **Rotate via CLI.** `probe` again, enter the new password twice. Expect
   "password CHANGED", then session, SLIM hello, signout. Confirms 2-5.
3. **Old password is dead.** `probe` with the old password → `AuthFailed`.
4. **New password works.** `probe` with the new one → no challenge.
5. **Policy rejection.** With another expired account (or after expiry again), try
   a password the policy refuses. Expect `AuthFailed("password change rejected: …")`,
   not a hang or a retry loop.
6. **GUI desktop.** Expire again; connect from the app. Dialog shows the gateway's
   prompt → submit → tunnel up → profile password updated (check the DB / reconnect
   after restart). Cancel must leave the profile untouched.
7. **Reconnect after rotation.** With the tunnel up, drop the network briefly; the
   reconnect must log in with the NEW password (no second challenge, no AuthFailed).
8. **Android.** `bun run android:engine` first (regenerates `libvpn_engine.so`), then
   `android:dev`. Same flow as 6 through the drawer; confirm the prompt survives the
   `disconnected` that follows `password_expired`.

## If an assumption fails

- Field not found → log the response SHAPE only (key names, no values), then adjust
  `parse_auth_reply`.
- `MultiChallange` rejected (502 or similar) → compare request fields against a
  snx-rs capture before changing anything else.
- Retype rejected with the same password → try the 22/22/23 hypothesis: capture what
  differs in the reference's retype reply.
- Update the memory note `checkpoint-multichallange-password-rotation` with what was
  actually observed, and replace the "Unverified" section there.

## Review checklist (Check Point)

- [ ] Wire facts above confirmed or corrected, each with the source (live gateway).
- [ ] No password, `user_input`, `active_key` or raw response body appears in logs
      at any level, including the error paths of the new loop.
- [ ] Failure at every round leaves no leaked CCC session (compare gateway session
      count before/after).
- [ ] `MAX_CHALLENGE_ROUNDS` (4) is enough and cannot be looped by a hostile gateway.
- [ ] Android Kotlin and the Tauri-Android `vpn_notice` path compile and run (only
      the engine was compiled so far).
- [ ] Optional hardening: a local fake CCC server as an integration test so the
      loop is exercised in CI without a real account.
