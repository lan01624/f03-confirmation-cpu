# R18B4 one-shot recovery V1

Original run 38440650246 (attempt 1, commit 83858f4d675dc42d853a7d3506bd057566b9a0f5) is terminal INVALID_EXECUTION. Its markers and encrypted artifact remain preserved. The Owner reports baseline STARTED, SUCCEEDED RESULT and FAILED, no candidate STARTED and no complete result. This is Owner-supplied decrypted evidence; the agent has not read protected custody. In the original execute.py the only operation following durable RESULT and rows.append in the caught block is scratch.rmdir(). Cleanup failure therefore explains the contradictory receipts. The exact OS exception was not retained publicly and is not asserted as observed.

Production now calls finalize.cell through execute.batch. Scientific execution and validation exceptions create genuine FAILED records. FD-safe recursive removal handles empty/nonempty temporary directories and tolerates prior absence without following links. Cleanup and receipt-write errors stop as CUSTODY_FINALIZATION_FAILED, never as retrospective scientific INVALID_EXECUTION. RESULT is committed after cleanup; no fallible cleanup follows it. Failure encryption excludes only the designated per-fit scratch subtree, even when removal fails; all scientific outputs, worker logs and failure records remain encrypted. No seeds, numerical results or exception messages are printed publicly.

All frozen/ bytes, including workers, momentum=0.9 plus Nesterov candidate, patch, trusted entry, measurement, split, protocol, statistics and dependency locks are unchanged. RECOVERY_PROTOCOL.json is additive execution identity, not a revised scientific estimand. Exactly three new paired blocks and six full-fidelity fits: five epochs, 3910 updates each, 50000 TRAIN/10000 VALID, no TEST, original final class5/6 recall and paired-t95 df2. No failed-run result reuse/pooling, no automatic admission, no second human-review claim.

## Engineering evidence

Tests execute the actual execute.batch -> finalize.cell production path with deterministic interface fixtures, including empty/nonempty/absent scratch, worker failure and cleanup failure. These are engineering fixtures, not scientific evidence. The PR engineering workflow also performs one bounded Linux integration with six real sandbox synthetic micro-workers through batch/finalization and a two-worker deterministic replay. It checks pairing, retained receipt hashes, numerical outputs, Landlock/seccomp denials and scratch exclusion, with no real data, random confirmation draws, markers or production Environment access.

## One final authorization boundary

This PR proposes prospective activation. It must not be merged or production-dispatched before explicit final PI GO. The original confirmation.yml job is retired. Only recovery.yml can bind the new operation and new once-only public marker:
refs/tags/r18b4-public-recovery-confirmation-v1-consumed
Private reservation marker:
refs/tags/r18b4-f03-recovery-confirmation-v1-consumed
Neither is created during engineering. Preserve both original markers permanently.

After final GO, verify merged tree/manifest, fresh recovery marker absence and no recovery run. Prepare one additive private delegation and reserve its new private ref through authenticated manual Git; keep PR95 Draft. Owner signs a new reservation using the existing PI key. Dispatch recovery.yml exactly once on protected main, capture run/attempt/commit, prepare its authorization and review digest, and obtain genuine Owner PI-role and evaluator-role signatures offline. Validate all three signatures, frozen source, original chronology, recipient and exclusion commitment, install authority in the existing protected Environment, then Owner manually approves it. No ambiguous dispatch retry.

Before approval Owner personally uploads the original private-seeds.json bytes to Environment secret R18B4_PRIOR_SEED_MANIFEST without copying them to the agent, Git or public logs. Its fixed SHA256 is 36fd88a8f6f82113a5bfb03493498c9c107d7941c4c4a353f28365dbeeabd9a7. Full original permit binding, block schema and domain are checked before public claim; all three seeds plus historical nine are excluded during fresh CSPRNG sampling and verified off host. Never publish per-seed hashes or seed values. Existing public trust and keys are reused; both roles are honestly Owner-controlled.

Each fit is capped at 900 seconds, batch at 7200, workflow at 150 minutes, standard ubuntu-24.04 CPU with unchanged science environment. One-day encrypted artifact retention; existing custody limits and accepted $0 upload risk remain. Download immediately on any terminal outcome, preserve ZIP/ciphertext/provenance hashes. No retries, reset, outcome-dependent seed replacement or additional batch.

Reuse the existing offline Docker image/interpreters, mounting the reviewed recovery source at /opt/f03 read-only. Frozen verifier additionally checks the old/new seed disjointness and rejects any terminal cleanup/finalization/scientific failure. Owner alone decrypts and verifies complete six-fit outputs off host. Accept SUPPORTED/REFUTED/INCONCLUSIVE under the unchanged rule, retain harms and limits, return one consolidated private package, then close R18B4. No real confirmation is established by engineering PASS.
