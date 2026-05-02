# Publishing

Gramota packages are published to npm under the `@gramota/*` scope, using
[Changesets](https://github.com/changesets/changesets) for version
management and [`changesets/action`](https://github.com/changesets/action)
for automated publishing from CI.

## One-time setup

### 1. Create the npm scope

The first publish must be done by an account with rights to the
`@gramota` scope on npm. To create the scope (free, no org subscription
required for public packages):

```bash
# Log in as the account that owns the project
npm login

# Create the scope as a user (not a paid org)
npm access list packages @gramota   # if it errors, the scope is fresh
```

The `publishConfig.access: public` field in each `package.json` ensures
scoped packages are published as public (npm defaults scoped to private).

### 2. Generate an automation token

In your npm account → **Access Tokens** → **Generate New Token** →
**Automation** (bypasses 2FA for CI).

Copy the token (`npm_xxxxxx...`).

### 3. Add the token as a GitHub Actions secret

```bash
gh secret set NPM_TOKEN --repo gramota-org/gramota
# Paste the npm_xxxxxx... token when prompted
```

Verify:

```bash
gh secret list --repo gramota-org/gramota
```

You should see `NPM_TOKEN`.

## Day-to-day flow

### Adding a changeset to a PR

When you make a change that should ship to npm, run:

```bash
pnpm changeset
```

This walks you through:
1. Which packages changed
2. Whether each is a `major`, `minor`, or `patch` bump
3. A summary that becomes the CHANGELOG entry

It writes a markdown file under `.changeset/`. Commit that file alongside
your code change.

### Releasing

The release workflow (`.github/workflows/release.yml`) runs on every push
to `main` and operates in two modes:

**Mode 1 — there are pending changesets.** The action opens (or updates)
a PR titled "chore: release packages". This PR:
- Bumps every changed package's version
- Updates each affected package's CHANGELOG.md
- Deletes the consumed `.changeset/*.md` files

Review and merge the PR.

**Mode 2 — the Version PR was just merged.** No changesets remain, but
versions are bumped. The action runs `pnpm changeset publish`, which:
- Runs `npm publish` for every package whose version isn't on npm yet
- Creates a GitHub Release per published package
- Skips packages with `private: true` (currently `@gramota/demo` and `@gramota/e2e`)

### Manually publishing (initial release or hotfix)

For the **first ever publish** (or any time you skip the Version PR
flow), bump versions manually and run:

```bash
pnpm -r build
pnpm changeset publish   # uses local NPM_TOKEN from `npm login`
```

## Versioning policy

- **0.x.y** while the API is still settling. Breaking changes ship as
  minor bumps (0.1 → 0.2), not majors.
- **1.0.0** when the public API is frozen and we commit to semver. Target
  is "after 6 months of OSS use without churn."
- All workspace deps use `workspace:*` internally; pnpm replaces them
  with exact versions on publish (so `@gramota/verifier@0.1.0` will pin
  `@gramota/jose@0.1.0`).

## Provenance

The release workflow sets `NPM_CONFIG_PROVENANCE=true` and uses
`id-token: write` permissions, so every published package has a
[provenance attestation](https://docs.npmjs.com/generating-provenance-statements)
linking it to the source commit on GitHub. This shows up as a green
"Provenance" badge on npmjs.com.

## Troubleshooting

**`E403: 402 Payment Required`** on first publish. The npm account
hasn't created the scope yet, OR the package is being published as
private (default for scoped). Check that `publishConfig.access: "public"`
is in each `package.json` (it is, for all our publishable packages).

**`E401: Unauthorized`**. The NPM_TOKEN secret is missing, expired, or
not an Automation-type token (Publish-type tokens require 2FA codes that
CI can't provide).

**Version PR doesn't open.** The action only opens a PR if there are
`.changeset/*.md` files to process. If you didn't run `pnpm changeset`,
add one and push.

**`workspace:*` survives in published tarballs.** This means the package
was zipped with `npm pack` instead of `pnpm pack`. Always use pnpm for
packing — npm doesn't understand workspace protocol.
