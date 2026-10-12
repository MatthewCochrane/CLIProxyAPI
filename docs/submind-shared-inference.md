# Explicit shared inference access

`CLIPROXY_SHARED_KEYS_ENABLED=true` admits the proxy's configured `api-keys`
alongside the existing dedicated environment-key verifier. The default is off;
existing deployments retain their previous authentication behavior.

- Only a single `Authorization: Bearer ...` credential is accepted by this path.
- Configuration retains the existing private key source. The access manager
  compares SHA-256 digests and returns the non-secret `shared-pool` principal.
- Managed-prefix credentials always use the dedicated verifier. Malformed,
  revoked or mixed managed credentials never fall through to shared access.
- Arbitrary/plugin access providers are not a shared-key fallback.
- Shared credentials must differ from private control and observer credentials;
  startup and subsequent configuration reloads enforce that separation.
- A valid reload replaces the shared snapshot. Invalid reloads preserve the last
  valid configuration. An empty key list removes shared access.
- Shared access does not issue/revoke environment keys or modify OAuth account
  files. Disabling a client removes its local provider configuration/credential
  copy, not the shared proxy key. Shared-key rotation affects every client.

The explicit flag requires the reviewed private control/observer configuration.
Do not put control credentials in inference clients or expose the private
control listener through the inference endpoint.

## Optional private account controls

`CLIPROXY_CONTROL_ACCOUNTS_ENABLED=true` enables account controls on that same
independently authenticated literal-loopback listener. It is off by default and
requires the reviewed control/observer roles plus an owned private auth directory.
The inference credential never grants control access. Origin, Cookie, non-loopback
and incorrect control-bearer requests are refused before account admission.

- `GET /v1/control/accounts` returns public hashed identity, email, authorization,
  desired inclusion, routing availability and revision for persistent Codex
  accounts. It never returns filenames or credentials.
- `POST /v1/control/accounts/:id/membership` takes `operationId`,
  `expectedRevision` and `included`. `POST .../:id/retire` takes the first two.
  Account IDs are 64 lowercase hexadecimal characters; operation IDs are 32.
  Missing or null revisions are invalid. The existing atomic token writer saves
  membership before runtime publication and synchronous model updates.
- `POST /v1/control/account-authorizations` takes `attemptId`, `targetId` and
  `expectedRevision`. New identity uses an empty target and revision zero.
  `GET` and `DELETE .../:attemptId` observe and cancel the same attempt. New
  accounts start excluded; targeted reauthorization preserves inclusion and
  rejects a different provider identity without replacing credentials.

Unknown replies use the same operation, not invented success or another OAuth.
Cancellation of an unknown attempt persists a tombstone before acknowledgment.
Pending OAuth expires on restart; uncertain commits reconcile against their
persisted operation. Challenges are transient. Private `.receipt` files hold
narrow operation receipts and are ignored by the auth JSON loader. Limits are
eight active and 1024 retained authorization attempts, with a 15-minute
credential-acquisition deadline.

Remove membership affects future selection and refresh, not active requests or
provider revocation. Retirement keeps an excluded tombstone; fresh authorization
of that identity reuses one owner and starts excluded. Reauthorization fences late
old refreshes. Equal-revision stale watcher snapshots cannot restore old tokens
or control fields. Unrelated accounts and inference/key/observer roles retain
their behavior.

Submind's `POOLED_CODEX_ACCOUNTS_ENABLED` and existing server-side control URL/token
provide the UI gateway. Legacy credentials, enrollment and assignment are not
prerequisites. No browser receives the private bearer or upstream tokens.

## Named observations for consolidated account cards

With the existing private account role enabled, `GET /v1/control/accounts/observations`
adds a backward-compatible read endpoint. The original `/v1/control/accounts`
inventory and account mutations retain their existing shapes. The new response
contains generated/start timestamps and named rows with the original public
account handle, allowlisted provider/plan, eligibility, cooldown, passive quota
windows and request-attempt counters. Counters belong to current registration
epochs; an untracked or replaced epoch is unknown rather than zero. Incomplete
counter coverage makes the aggregate unknown. Account IDs, tokens, file paths and
internal keyed observer handles are never projected.

Plans are read only from an already-owned ID token whose account identity matches
the credential. Unknown claims remain unknown. Subscription expiry is not a
payment date. Quota freshness and reset timing are observations, not proof that
an account can use every model. Reading this endpoint does not make an inference
request, refresh a token or change membership. It retains the same literal
loopback, independent control bearer and browser-origin/cookie rejection gates.
