# Rauthy PR #1585 — re-request-review nudge

**PR:** https://github.com/sebadob/rauthy/pull/1585 — "Add API keys advanced
bootstrap JSON" (your PR). Live state at drafting: `open`, `mergeable: true`,
review decision `CHANGES_REQUESTED`, head `21eff77`, last updated 2026-06-02 —
the inline nit was addressed but **no re-request-review event** is recorded, so
it's sitting in sebadob's blind spot. The only action needed is a nudge.

**This is the only live Rauthy work this cycle.** Do not open a `providers.json`
PR — sebadob's stance on #1554 is "I might add that as opt-in, but it has no
priority right now," and he prefers a future encrypted-container mechanism. The
auto-link + emailed-set-password behaviors we depend on are already shipped
(#1153), so there's nothing else to file.

---

## Step 1 — comment on the PR

> Thanks for the review. I've addressed the change request in the latest push
> (`21eff77`):
> - dropped the unnecessary `Serialize` derive — the bootstrap type is
>   deserialize-only;
> - switched to manual validation as suggested.
>
> `just fmt` and `just pre-pr-checks` are green. This keeps the api_keys path
> purely first-boot/empty-DB — it runs under the same empty-`jwks`-table gate as
> the existing `clients.json`/`users.json` bootstrap, so it's INSERT-only and
> never touches a running instance (not live reconciliation), and the docs note
> still recommends a short-lived key. Re-requesting review when you have a moment
> — no rush, just flagging it's ready since there wasn't a re-request event.

## Step 2 — re-request review

In the PR's **Reviewers** panel, click the re-request (↻) icon next to
`@sebadob`. This is the event that actually moves it out of `CHANGES_REQUESTED`
in his queue; the comment alone won't.

## Step 3 — confirm gates locally before nudging

```sh
just fmt
just pre-pr-checks
```

Make sure both pass on `21eff77` (or push a fresh head and update the SHA in the
comment) so the nudge isn't immediately bounced by CI.

---

**Framing reminder:** everything stays "extend the existing Advanced
Bootstrapping file mechanism." Never reframe as a new token primitive (#1584:
"only increase code complexity") or a live reconcile API. Note this shape may be
reworked if sebadob ships the encrypted-container mechanism — our reliance on
`api_keys.json` is transitional, not load-bearing.
