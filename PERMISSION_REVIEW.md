# Personal native permission review v1

This personal-fork extension advertises `x.ai/permissionReview` in ACP agent
capability metadata with `version: 1`, `build: personal-native-review-v1`, and
`inputBindings: sha256`. It does not change the standard manual ACP response.

Permission request `_meta["x.ai/permissionReview"]` contains `version`,
`sessionId`, `toolCallId`, `nonce`, `policyGeneration` (decimal string),
`actionDigest` (SHA-256), required `securityFindings` (array of native static
finding tokens, including an empty array), and `eligibility` with `kind` and `reason`.
Only `classifier_hold` is reviewable. Explicit policy and hook asks, protected
edits, native matcher asks (including fail-closed asks), opaque shell and
unavailable classifiers remain `human_required`. EnvInjection, ExecOrAmbientGit
and SpecialExecSurface findings are conservatively unsupported.
The digest covers native access, execution cwd, the serialized tool update and
security findings.
A fresh nonce binds the response to this pending session and tool call.

A reviewer response selects the existing `allow-once` or `reject-once` ACP
option and includes this metadata object:

```json
{
  "version": 1,
  "nonce": "copied from request",
  "policyGeneration": "copied from request",
  "actionDigest": "copied from request",
  "decision": "allow_once",
  "inputBindings": [{"path": "/absolute/canonical/file", "sha256": "64 lowercase hex characters"}]
}
```

`reject_action` selects `reject-once` and may include `feedback`. Unknown fields,
wrong bindings, ineligible origin and persistent options fail closed. Rejection
produces a failed tool result and continues the original prompt without creating
a user message. A response without extension metadata retains manual ACP behavior;
the proxy must never drop malformed review metadata and submit an ordinary allow.

Bash, Edit, MCP and generic Tool approvals require at least one input binding.
Native checks unique absolute canonical regular-file paths and SHA-256 bytes,
with at most 128 files and 512 MiB total. Empty bindings for those access kinds
reject. The proxy must establish adequate context and refuse insufficient scope.
Native does not prove that the supplied list includes all relevant resources.
The execution guard rechecks hashes and effective generation at shared dispatch,
after batch preparation, later prompts/hooks and the file-lock wait, including
auth retries. Cancellation and send-now revoke pending guards synchronously.
A stale guard returns a failed tool result with feedback and Continue.
Hashes do not freeze files after this final check, parent directories, unlisted transitive
inputs, environment, network responses, executable resolution or future state.
This protocol is not an execution sandbox or an atomic filesystem snapshot.

The session's compiled policy is immutable. Before reviewed execution native
reruns its actual policy matcher, checks queued mode/classifier/context mutation
generation, checks cancellation and rejects changed persisted grants. Hard denies
remain native. Reviewed allows neither persist grants nor become user approvals
in classifier history. No blanket shell ban is introduced.

## Validation boundary

Focused response tests cover valid binding, stale nonce/generation/digest,
persistent option refusal, missing option, human-required refusal, malformed
answers and rejection feedback. Full manager race tests, file mutation tests,
real ACP timeout/cancellation, rejection continuation and historical wrapper
replays still require execution evidence. Formatting and source tests alone do
not prove installed T3 behavior. Linux and Mac production acceptance belongs to
the integration owner and must identify exact built and installed artifacts.

The v2 fix changes internal guard transport only. V3 adds required request
`securityFindings`; response keys and protocol version remain 1.
The guard mutation regression is a focused test, not a real two-call ACP replay.

## Broad grants and one-use review

A Bash broad-grant floor prevents blanket, prefix/glob or sandbox auto-allow.
It requires classification; it is not a categorical human-only restriction.
`unvetted_env` and `file_write` therefore do not alone exclude a one-use review
following an affirmative native classifier Block. Native matcher Allow is
required before eligibility and again when accepting the response. Explicit
asks, fail-closed native asks, hook asks and protected targets remain authoritative.
No helper path is exempted and no persistent grant is created.

Eligible does not mean safe. The independent reviewer must account for native
findings and reject unsupported implicit inputs and execution-routing variables.
For example, PYTHONPATH can import mutable sitecustomize.py before a listed
Python helper or script runs. Hashing those listed scripts does not authorize or
freeze that implicit code. Native checks only the supplied bindings. Supported
scope is a reviewable one-use action whose relevant inputs the reviewer can
establish; incomplete context must fail closed at the proxy.

## Persisted permission freshness

V4 binds the current bytes (or absence) of every configured grant-store candidate,
including shared, client-specific and legacy fallback paths. Dispatch rehashes
those candidates and refuses any difference, unreadable/nonregular file, or file
larger than 4 MiB. It does not parse a second policy implementation. Store reloads,
recorded prompt mutations and session edit-grant changes revoke earlier guards
through synchronized generation increments. Manual permission outcomes retain
existing behavior; only outstanding reviewed authority expires.

The compiled active policy remains the session policy. Changing disk configuration
is not claimed to reload that compiled policy. Store fingerprints and input hashes
close observable preparation delays, not atomic races after the final check or
external changes restored between observations. Focused guard tests cover direct
external deny creation without an actor reload and generation revocation despite
restored store bytes; real two-call ACP and manual RejectAlways replays remain
integration verification obligations.

## Native state and the bound baseline

V5 Auto requests force the existing native store loader to read state between
matching content snapshots before evaluating permission. The loaded state is
merged through the native state merge, retaining session restrictions. This
bypasses the legacy metadata cache for review baseline establishment, including
shared fallback changes and same-length changes with restored modification time.
A changed baseline revokes previously prepared guards. Invalid UTF-8, malformed
TOML, unreadable candidates or concurrent changes reject the request. Candidate
syntax checks use the same native PermissionState parser; source selection and
legacy precedence remain in the existing loader. No snapshot can qualify solely
because its bytes match a later snapshot without this native state read.

The actor regression starts with an absent desktop store and a shared fallback,
warms the actor, then changes a shared denial without changing length or mtime.
It asserts native rejection before any permission callback and fail-closed
behavior for malformed state. Added tests have not been run in this writer lane.

V6 synchronizes the metadata cache only after the native read and both content
and metadata stability checks succeed. Acceptance therefore compares against
the evaluated baseline, rather than rejecting an unchanged baseline because of
an older cached signature. An actor test supplies a valid bound allow after a
benign primary-store update and checks both successful Allow with a valid guard
and rejection when the callback writes a new deny. V6 tests and builds remain
unrun in this writer lane.
