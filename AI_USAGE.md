# AI Tooling Transparency Statement (Rule P-05)

**Project:** PromptArmor — an LLM prompt-injection firewall
**Event:** All Day AI Hackathon 2026, BUILD track
**Participant:** lz (solo entry)

This statement discloses, accurately and without embellishment, how AI tools
were used in creating this project.

## Division of work

| Part of the project | Who / what |
|---|---|
| Problem selection, project concept, scope and track choice | Participant (lz), human decision |
| Detection approach (normalization pipeline, weighted rule families, allow/flag/block policy) | Designed by the participant; implemented with AI assistance (see below) |
| Source code (`src/detector.js`, `src/worker.js`, `tests/run.mjs`) | Drafted and written with **Muse (Meta Muse Spark)** acting as an AI coding assistant, under the participant's direction |
| Test corpus (`data/payloads.json`) | Co-authored: attack families and benign false-positive traps chosen by the participant; individual payloads drafted with AI assistance and reviewed by the participant |
| Detection rules and score thresholds | **Human-reviewed and approved**: every rule family, weight and threshold in the shipped detector was reviewed and ratified by the participant before submission; adjustments during testing (e.g. removing an over-broad pattern that false-flagged "ignore the typo in my previous message", and restoring the terms `base64`/`rot13` after leetspeak folding) were verified against the test corpus |
| Documentation (README, this statement, demo script) | Drafted with AI assistance; facts and all reported numbers checked against actual local test runs by the tooling (no invented metrics) |
| Deployment configuration (`wrangler.toml`) | Prepared with AI assistance; contains no secrets — the upstream API key is supplied only via `wrangler secret put` at deploy time |

## Tools used

- **Muse (Meta Muse Spark)** — AI assistant used for code drafting,
  documentation drafting, and test iteration, as described above.
- **Node.js** — local test runtime for the detector test harness.
- **Cloudflare Workers / Wrangler** — deployment platform and tooling.

No AI tool was used to fabricate test results, user data, or endorsements.
All quantitative claims in the README come from running `tests/run.mjs`
against the corpus in this repository and are reproducible via the worker's
`GET /api/test` endpoint after deployment.

## Confirmation

I confirm that the description above accurately reflects how AI tools were
used in this project.

Participant (lz): ______________________  Date: ______________
