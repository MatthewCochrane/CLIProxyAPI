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
