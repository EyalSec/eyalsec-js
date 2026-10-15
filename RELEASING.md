# Releasing

Releases go to npm from GitHub Actions (`.github/workflows/publish.yml`) when a
version tag is pushed. Nobody publishes from a laptop.

## Once

1. Create the npm organization `eyalsec` (it reserves the `@eyalsec` scope too)
   and make sure the account that owns it has two-factor authentication on.
2. Create a **granular access token** on npmjs.com: read and write, limited to
   the `eyalsec` package (for the very first publish, before the package
   exists, scope it to "All packages" of the account or organization, then
   narrow it afterwards). Give it an expiry.
3. In this repository, open Settings > Environments > **npm** (it exists
   already, and only `v*` tags may deploy to it) and add the token as the
   environment secret **NPM_TOKEN**. Adding a required reviewer there makes
   every publish wait for a click.

## Every release

1. Update `version` in `package.json` and `src/version.ts` (a test checks they
   agree), and add the entry to `CHANGELOG.md`.
2. Merge to `main` with CI green.
3. Tag and push:

   ```bash
   git tag v0.1.0
   git push origin v0.1.0
   ```

4. Watch the **Publish to npm** run. Then check
   <https://www.npmjs.com/package/eyalsec> shows the version with its
   provenance badge, and `npm view eyalsec version` prints it.

A version can never be published twice. If a release is wrong, fix it and
publish the next patch version.

## Later: publishing without a token

Once the package exists, npm's trusted publishing can replace the token:
on npmjs.com, under the package's settings, add this repository and
`publish.yml` as a trusted publisher, then delete `NPM_TOKEN`. The workflow
then needs npm 11.5.1 or newer (`npm install -g npm@latest` before
`npm publish`) and no `NODE_AUTH_TOKEN`.
