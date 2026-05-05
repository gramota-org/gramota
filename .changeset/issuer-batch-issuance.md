---
"@gramota/issuer": minor
---

Add `Issuer.issueBatch()` (and `issuer.credentials.issueBatch()`) for OID4VCI
Draft 14/15 batch issuance.

The EU reference wallet asks for `numberOfCredentials = 10` per issuance so
each presentation can use a fresh, unlinkable credential (one-time-use
policy). Before this change, callers had to loop `issue()` themselves;
they now pass an array of per-credential entries (each with its own
`holderKey`, optional `credentialId`, optional `status`) plus shared
options (subject, vct, expiry) and get back `readonly IssueResult[]`.

```ts
const results = await issuer.credentials.issueBatch({
  subject: { given_name: "Alice", birthdate: "1985-06-15" },
  selectivelyDisclosable: ["given_name", "birthdate"],
  vct: "https://credentials.example.com/identity_v1",
  expiresIn: 365 * 24 * 3600,
  credentials: holderKeys.map((holderKey) => ({ holderKey })),
});
// results[i].token is bound to holderKeys[i] with fresh disclosure salts.
```

Each credential gets a distinct `credentialId`, fresh random salts (so
two credentials over the same claims are unlinkable on the wire), and
its own `cnf.jwk` binding. Shared `issuedAt` is pinned once for the
batch so every credential reports the same `iat`.

New exports: `BatchIssueOptions`, `BatchIssueEntry`, error code
`issuer.batch_empty`. No breaking changes to `issue()`.
