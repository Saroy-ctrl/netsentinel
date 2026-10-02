# Contributing

## Flow
1. Pick the next unchecked task in your track issue (`track:M1` … `track:M5`). Order matters, and ★ tasks unblock teammates.
2. Branch: `M<track>/<task-number>-<slug>`, e.g. `M3/04-flows-endpoint`.
3. Open a PR to `main` using the template. You need CI green and one review.
4. Tick the box in your track issue when it merges.

## The contract rule
`nscore/contracts/` is how five people build in parallel without waiting on each other. To change it:
- you need approval from **M3** (API owner) **plus one consumer** of the changed model
- bump `CONTRACT_VERSION` in `schemas.py`
- regenerate the fixtures: `python -m nscore.contracts.fixtures.make_fixtures` (CI fails if you forget)

If the contract doesn't fit your need, open a contract PR. Don't work around it in your own code.

## Never commit
`data/`, `artifacts/`, `*.joblib`, `*.pcap`, `.env`, or any key. Gitleaks runs on every PR.

## Honesty rule
No metric goes in the deck or README unless the repo can reproduce it (script + fixed split + bundle version).

## Safety rule (from the PS)
Only capture or scan machines we own (host-only VM lab). Never touch a network we don't have written permission to test.
