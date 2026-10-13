# F03 public confirmation transport V1

This repository is a minimal prospective execution transport for the frozen
`r18b4-f03-whole-patch-confirmation-v1` experiment. Production is disabled in
`activation.json`. No actual independent confirmation is supplied by this release.

The original baseline/candidate worker bytes, original patch, accepted two-change
trusted entry, Landlock/seccomp boundary, CPU lock, protocol and ConfirmationSpec
are committed under `frozen/`. Four baseline functions, four data/hash functions,
three receipt/metric functions and two statistical/seed-validation functions are
exact source slices with minimal import headers. No model/optimizer/forward/loss/
order/metric implementation has been rewritten. The private source-to-public
mapping documents every extraction. Full-file parity is claimed only for exact
copies; the transport is a new prospective contract.

No dataset files, Agent, source-repository Git metadata, private ledgers, historical
action/API logs, prior outcome cards or evaluator keys are included. The frozen
protocol itself contains a historical magnitude in its margin disclaimer; Owner
publication review must explicitly include that exact original document.

## Publication and synthetic qualification

Owner must review the external complete publication inventory and its SHA256
before any public push. `MANIFEST.json` commits every public file except itself;
the external inventory includes `MANIFEST.json` and therefore closes that boundary.
Only the exact reviewed inventory may be staged in a fresh Git repository.

Protect `main` (required PR review, no force-push or deletion, include administrators)
before dispatch. Configure Actions to permit the pinned setup-python and artifact
actions. Manually dispatch **synthetic.yml** on protected `main`, attempt 1. It uses
standard `ubuntu-24.04` with Python 3.12.14 and the exact original CPU package lock
in a fresh venv. There is no fallback package, Python, OS, sandbox or device.

The workflow uses anonymous HTTPS to fetch only this public repository. No PAT or
repository token is passed to checkout, dependency installation, tests or fitting.
The synthetic path does not download any dataset or generate confirmation seeds.
The fixed engineering fixture 7101 is not a confirmation seed manifest. It runs
four one-update, 20-TRAIN/20-VALID synthetic micro-tests: each exact worker twice.
It checks numerical replay, paired initialization/order, recomputed metrics, and
actual denial of private and TEST-canary files, network and child processes.

Its only success classification is `PUBLIC_RUNNER_SYNTHETIC_QUALIFIED`. Save the
actual run ID, attempt, SHA, manifest digest, runner image/kernel/CPU, source
identity and qualification JSON promptly; artifact retention is one day. A green
check is engineering evidence only. It never replaces missing private CI checks.

GitHub documents standard public hosted runners as free; availability despite the
private quota must still be established by an actual run:
https://docs.github.com/en/actions/how-tos/write-workflows/choose-where-workflows-run/choose-the-runner-for-a-job

## Independent evaluator and prospective production

Do not dispatch `confirmation.yml` in this release. A later separately reviewed
activation must first update `activation.json`, rebuild the complete manifest,
obtain Owner publication approval for new bytes, freeze the resulting public
commit and obtain genuine PI/evaluator approval. Synthetic success alone grants
no fit authority. No evaluator is appointed by this repository.

Appoint an independent human distinct from `lan01624`, with a verified GitHub user
ID and independently exchanged Ed25519 public signing key. The evaluator alone
generates a NEW RSA-3072 recipient key off host and keeps its private half entirely
outside GitHub, Codex and the Agent. Never use prior Owner keys. The PI uses a
distinct off-host Ed25519 signing key. Fixture keys in tests are synthetic only.

Configure Environment `r18b4-independent-evaluator` with only that evaluator as
required reviewer, prevent self-review, disable administrator bypass, and a custom
deployment policy allowing branch `main` only (no tags). Protect main separately.
Review current GitHub protection semantics:
https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments

The gate reads repository/protection/main metadata anonymously, failing closed if
GitHub denies those reads or reports a mismatch. The public job's token is passed
only to one `POST /git/refs` for the fixed public marker. It never accesses the
private source repository. Administrator control of repository code, settings and
Environment secrets remains; these controls are not protection from a malicious
administrator or GitHub host. Off-host key custody protects decryption, while
independent artifact/signature review determines what evidence is accepted.

The evaluator installs only public trust material in `R18B4_TRUST_JSON`:
`pi_signing_public_pem`, `pi_signing_sha256`, `evaluator_signing_public_pem`,
`evaluator_signing_sha256`, `evaluator_login`, `evaluator_id`,
`recipient_public_pem`, `recipient_sha256`. Fingerprints are SHA256 of DER
SubjectPublicKeyInfo. It contains no private key.

`R18B4_SIGNED_AUTHORIZATION` is a strict bundle with `authorization`,
`pi_signature`, `evaluator_signature`, `reservation`, `reservation_pi_signature`.
See `validate_authority` in `authorize.py` for the exact versioned schema. Both
signatures bind canonical UTF-8 sorted compact JSON of the same authorization,
including actual run ID/attempt, exact public commit/manifest, complete original
science identity, recipient, signed private reservation digest and <=24h expiry.
The signed `approval_digest` must equal separate evaluator-controlled Environment
secret `R18B4_REVIEWER_APPROVAL_SHA256`, the digest of the evaluator's retained
substantive review. The actual run ID is available while the job waits for
Environment review; install this run-specific authorization before approving it.

The private reservation must already have been signed and committed and the old
private consumed marker durably claimed, verified by PI and evaluator with their
ordinary private access. The public job verifies their signed delegation; it
cannot independently inspect the private repository. The private handoff describes
the manual reservation procedure. No reservation is created by publishing this code.

Order: signatures/protections -> exact runtime/TRAIN hashes/synthetic sandbox ->
atomic public marker -> durable execution/seed-generation records -> CSPRNG three
fresh blocks excluding all nine historical seeds -> six original fits. Any
failure, rejected seed, interruption, missing artifact or uncertainty is terminal
until PI review. Never rerun a production job, replace seeds, reset either marker,
or select completed blocks. A local failed claim is also permanently recorded.

All raw receipts, seeds, numerical findings, logs and execution bytes stay in
evaluator custody. Only AES-256-GCM/RSA-OAEP-SHA256 encrypted custody and a minimal
opaque receipt leave the job. Fitting runs in the frozen science venv; signing and
encryption use a separate fixed crypto venv. Artifacts expire in one day. No raw
output is written to job summaries or logs. Termination may prevent sealing or
upload; the consumed marker still makes that a terminal lost run.

## Off-host verification and return bridge

Evaluator downloads the artifact, independently verifies repository ID, commit,
workflow path/run/attempt, release/protocol/manifest and encrypted file hash using
GitHub provenance, and supplies those expected values independently of the artifact.
On their own Linux x86_64 host, use separate exact science and crypto venvs.
`verify_custody.py decrypt` accepts the recipient private key only OFF HOST and
checks AEAD, provenance, paths and every custody file hash before extraction.
Never run that command inside GitHub or give its private-key argument to Codex.

`verify_custody.py verify` uses the original numerical runtime to check six full
receipts, split/data hashes, exact runtime bytes, source hashes, all epochs, original
metrics, paired initialization/order, per-class harms and original t95 df2 result.
Pass independently obtained public trust to `--external-trust` and the separate
crypto interpreter to `--crypto-python`; archive-supplied keys are not trusted.
Its detailed report stays private. The sample size remains three seed blocks on
the same VALID data, with a conditional normal approximation, no independent-data
generalization and no automatic scientific admission.

After substantive independent quality review the evaluator creates and signs only
the sanitized receipt accepted by the private `r18b4_public_import.py`. The Owner
separately verifies/imports it through ordinary manual Git/private PR, without
private Actions. No public workflow writes to the private repository, and no
`VALIDATED`, `ADMITTED` or LessonCard transition is automatic.

## Local engineering checks

Set `PYTHONDONTWRITEBYTECODE=1` to keep generated caches out of the strict inventory.
Run `python -B -m unittest discover -s tests -p test_static.py` without numerical
imports, and `python -B -m unittest discover -s tests -p test_security.py` in the
separate crypto environment. These unit fixtures do not establish hosted Linux
qualification or independent human review. `qualify.py` intentionally requires
the real protected public Actions context and frozen runtime.
