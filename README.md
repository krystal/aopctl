# aopctl

`aopctl` is a command-line tool for Cloudflare's per-hostname
[Authenticated Origin Pulls](https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/set-up/per-hostname/)
(AOP). It creates a dedicated AOP client CA, issues leaf certificates from it,
uploads them to Cloudflare, points hostnames at them, and deletes the ones you
no longer use.

It covers the Cloudflare steps of [Set up Cloudflare][plugin-setup] for
[traefik-plugin-cloudflare-origin][plugin], the Traefik plugin that verifies
these certificates at the origin. It does not manage zone-level AOP, DNS, zone
settings or Traefik configuration. The one exception is
`aopctl ca show --secret`, which prints the CA Secret from the plugin's
[example 1][plugin-example-1].

Per-hostname AOP with your own CA lets an origin tell Cloudflare requests for
your hostnames apart from requests Cloudflare proxies for anyone else. The
plugin README's [security model][plugin-security] explains why neither
Cloudflare's IP ranges nor its shared AOP certificate can do that.

`aopctl` reads secrets from environment variables, never writes a key to disk,
and uses only the Go standard library.

[plugin]: https://github.com/krystal/traefik-plugin-cloudflare-origin
[plugin-security]: https://github.com/krystal/traefik-plugin-cloudflare-origin#security-model
[plugin-setup]: https://github.com/krystal/traefik-plugin-cloudflare-origin#set-up-cloudflare
[plugin-example-1]: https://github.com/krystal/traefik-plugin-cloudflare-origin#1-gate-one-service
[plugin-pin]: https://github.com/krystal/traefik-plugin-cloudflare-origin#pin-the-ca-or-the-client-certificate
[plugin-revoke]: https://github.com/krystal/traefik-plugin-cloudflare-origin#revoke-a-leaked-client-certificate
[plugin-rotate-ca]: https://github.com/krystal/traefik-plugin-cloudflare-origin#rotate-the-ca
[plugin-access-logs]: https://github.com/krystal/traefik-plugin-cloudflare-origin#access-logs

## Install

Prebuilt binaries cover Linux and macOS on amd64 and arm64. There are no
Windows builds: `leaf prune` asks for confirmation through `/dev/tty`.

### With mise

The [`github` backend](https://mise.jdx.dev/dev-tools/backends/github.html)
installs the release archive for your platform:

```sh
mise use -g github:krystal/aopctl
```

If your mise configuration sets `minimum_release_age`, mise installs a new
release only once it is that old, unless you add `github:krystal/aopctl` to
`minimum_release_age_excludes`.

### With go install

`go install` builds `aopctl` from source and needs Go 1.22 or later:

```sh
go install github.com/krystal/aopctl@latest
```

mise's `go` backend does the same through mise:

```sh
mise use -g go:github.com/krystal/aopctl
```

### From a release archive

Each [release](https://github.com/krystal/aopctl/releases) has a `.tar.gz`
archive per platform, holding the `aopctl` binary, `LICENSE`, `README.md` and
`CHANGELOG.md`, and a checksums file. To install a release on Linux amd64:

```sh
version=0.1.0 # the release to install, without the leading v
base="https://github.com/krystal/aopctl/releases/download/v${version}"
curl -fsSLO "${base}/aopctl_${version}_linux_amd64.tar.gz"
curl -fsSLO "${base}/aopctl_${version}_checksums.txt"
sha256sum --check --ignore-missing "aopctl_${version}_checksums.txt"
tar -xzf "aopctl_${version}_linux_amd64.tar.gz" aopctl
```

For other platforms, replace `linux_amd64` with `linux_arm64`, `darwin_amd64`
or `darwin_arm64`. On macOS, check the checksum with `shasum -a 256 --check`
instead of `sha256sum --check`. Then move `aopctl` to a directory on your
`PATH`.

Releases are GitHub
[immutable releases](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases),
so GitHub publishes an attestation of each release's tag, commit and assets.
To check a downloaded archive against it with the GitHub CLI:

```sh
gh release verify-asset --repo krystal/aopctl "v${version}" "aopctl_${version}_linux_amd64.tar.gz"
```

### Check the version

```sh
aopctl version
```

Release archives and `go install github.com/krystal/aopctl@<version>` report
the release, for example `aopctl v0.1.0`. A build from a checkout reports the
version Go records for it, or `(devel)`.

## Configure

`aopctl` reads its configuration from environment variables, so any way of
setting them works. It contains no 1Password code, but the examples here use
1Password's `op run`: keep `op://` references in an env file, and run each
`leaf` command through `op run --env-file`.

```sh
# aop.env
AOP_CA_CERT=op://<vault>/<item>/ca_cert
AOP_CA_KEY=op://<vault>/<item>/ca_key
CLOUDFLARE_API_TOKEN=op://<vault>/<token item>/credential
CLOUDFLARE_ZONE_ID=<zone ID>
AOP_HOSTNAMES=app.example.com,admin.example.com
```

```sh
op run --env-file aop.env -- aopctl leaf status
```

| Variable               | Used by                                                                     |
| ---------------------- | --------------------------------------------------------------------------- |
| `AOP_CA_CERT`          | `leaf issue`, `leaf associate` and `leaf prune`; optional for `leaf status` |
| `AOP_CA_KEY`           | `leaf issue`, as a PKCS#8 PEM                                               |
| `CLOUDFLARE_API_TOKEN` | every `leaf` command                                                        |
| `CLOUDFLARE_ZONE_ID`   | every `leaf` command                                                        |
| `AOP_HOSTNAMES`        | every `leaf` command, comma- or whitespace-separated                        |

`AOP_HOSTNAMES` must list every hostname this CA serves in the zone.
Cloudflare has no API that lists all hostname associations, so `aopctl` only
sees the hostnames you list. Repeated `--hostname` flags replace the variable.
A certificate can serve at most 100 hostnames.

Create the API token with the **Zone > SSL and Certificates > Edit**
permission for the zone. `leaf status` only needs Read, but every other `leaf`
command writes. Account-owned tokens work. They fail Cloudflare's token verify
endpoint, which `aopctl` does not use.

## Commands

| Command                              | What it does                                                                    |
| ------------------------------------ | ------------------------------------------------------------------------------- |
| `aopctl ca create`                   | Create a CA and print a 1Password item template                                 |
| `aopctl ca show`                     | Describe the CA certificate on stdin, or print it as a Kubernetes Secret        |
| `aopctl leaf issue`                  | Issue a leaf, upload it and point the listed hostnames at it                    |
| `aopctl leaf associate --cert-id ID` | Point the listed hostnames at an existing leaf, to resume or roll back an issue |
| `aopctl leaf status`                 | List the zone's hostname certificates and the listed hostnames' associations    |
| `aopctl leaf prune --cert-id ID...`  | Delete the named certificates after checking that no listed hostname uses them  |
| `aopctl version`                     | Print the `aopctl` version                                                      |

Run `aopctl <command> -h` for each command's flags. `aopctl` exits with 0 on
success, 1 on errors and 2 on usage errors.

`aopctl ca create` makes an EC P-256 key (`--key-type rsa-3072` for RSA) and a
CA certificate valid for 3650 days (`--days`). The CA can sign leaves only:
CA:TRUE with a path length of 0, certificate and CRL signing, and no extended
key usage. It writes a 1Password item template to stdout, with the fields
`ca_cert`, `ca_key` (concealed) and `fingerprint_sha256`, and the fingerprint
to stderr. It needs no secrets, so run it outside `op run` and pipe it
straight into 1Password. It refuses to write to a terminal.

```sh
aopctl ca create --name "Example AOP CA" | op item create --vault <vault> -
```

Pin the fingerprint in the plugin's `clientCertFingerprints`. The plugin
README explains when to [pin the CA or the client certificate][plugin-pin].

`aopctl ca show` reads the CA certificate from stdin, not from the
environment, because `op run` masks secret values in a command's output,
including the certificate. It prints the fingerprint to pin, the validity and
the key type, and warns when the certificate does not match the CA profile.
With `--secret` it prints only the Secret:

```sh
op read "op://<vault>/<item>/ca_cert" | aopctl ca show
op read "op://<vault>/<item>/ca_cert" | aopctl ca show --secret cloudflare-aop-ca --namespace app
```

`aopctl leaf issue` issues an EC P-256 leaf (`--key-type rsa-3072` for RSA)
for client authentication, valid for 365 days (`--days`). Before it writes
anything, it checks that the zone has a free certificate slot (Cloudflare
allows 10) and reads each hostname's association. It refuses a hostname whose
association is disabled, since someone turned AOP off for it on purpose. It
then uploads the leaf, waits for Cloudflare to report it `active`, points all
listed hostnames at it in one request, and waits until each association is
`active`. `--dry-run` prints the plan and changes nothing. The leaf key is
only ever sent in the upload request. `leaf issue` never deletes a
certificate.

`aopctl leaf prune` deletes only the certificates named with `--cert-id`. It
refuses a certificate that is not signed by `AOP_CA_CERT` or that a listed
hostname uses, and checks the listed hostnames again just before each delete.
It shows a preview and asks for confirmation on the terminal, through
`/dev/tty` so the prompt works under `op run`, unless you pass `--yes`. A
certificate already being deleted is waited for, not deleted again.

`leaf issue`, `leaf associate` and `leaf prune` poll every 5 seconds within a
total budget for the whole command, `--timeout`, which defaults to 10
minutes. When the budget runs out, they report the last state they saw.

## Rotate the leaf certificate

When the plugin pins the CA, rotating the leaf needs no Traefik change.

1. Preview the rotation, and check the hostnames and the certificates they
   use now:

   ```sh
   op run --env-file aop.env -- aopctl leaf issue --dry-run
   ```

2. Issue and roll out the new leaf:

   ```sh
   op run --env-file aop.env -- aopctl leaf issue
   ```

   It prints the certificates the listed hostnames no longer use, and the
   `aopctl leaf prune` command that deletes them.
3. Check the result with `aopctl leaf status`, and check that requests through
   Cloudflare still reach the backend with the client IP, for example in the
   [access log][plugin-access-logs].
4. Prune the old certificates soon, with the printed command:

   ```sh
   op run --env-file aop.env -- aopctl leaf prune --cert-id <old ID> --hostname <hostname>...
   ```

   Cloudflare's documentation says that when several certificates exist, "the
   most recently deployed certificate will be the one enabled and used". That
   conflicts with choosing a certificate per hostname, so do not keep old
   certificates around.

An `active` status in the API does not prove which certificate Cloudflare
presents to your origin. Before the first production rollout, check it
against a staging origin: pin the new leaf's fingerprint, which `leaf issue`
prints, instead of the CA's on a staging hostname. Requests through
Cloudflare then pass only when Cloudflare presents the new leaf.

To rotate the CA itself, follow [Rotate the CA][plugin-rotate-ca] in the
plugin README. `aopctl leaf associate` and `aopctl leaf prune` only accept
certificates signed by `AOP_CA_CERT`, so roll back to, or prune, the old CA's
leaves with `AOP_CA_CERT` set to the old CA.

## Recover or roll back

If `leaf issue` fails after the upload, it prints the new certificate's ID,
each hostname's original and observed association, and the commands to
continue or undo the rollout:

- To resume, run the printed
  `aopctl leaf associate --cert-id <new ID> --hostname ...` command.
- To roll back, run the printed `aopctl leaf associate` commands, one per
  certificate the hostnames used before, each listing only that certificate's
  hostnames.
- `aopctl` never voids an association, so for hostnames that had none, it
  prints the API request that voids the new one. You can also remove it in
  the Cloudflare dashboard.

  ```text
  PUT /zones/{zone}/origin_tls_client_auth/hostnames
  {"config":[{"hostname":"<hostname>","cert_id":"<new ID>","enabled":null}]}
  ```

None of these needs a free certificate slot. `leaf associate` only accepts an
`active` certificate signed by `AOP_CA_CERT`, and `--dry-run` previews it.
During a CA rotation, the hostnames' original certificates are the old CA's,
so run the rollback commands with `AOP_CA_CERT` set to the old CA. `leaf
issue` marks each command that needs this.

If the new certificate never becomes active, `leaf issue` changes no hostname,
so there is nothing to resume or roll back. It prints the `aopctl leaf prune`
command that deletes the certificate, so you can run `leaf issue` again, and
the `aopctl leaf associate` command to use if it becomes active later.

If the upload fails without a usable response or with a server error, for
example on a timeout or an HTTP 5xx, `leaf issue` reports that the outcome is
unknown. Cloudflare may have created the certificate, so run
`aopctl leaf status` before you retry.

## If a leaf key leaks

Deleting a leaf from Cloudflare does not revoke it. Anyone with its key can
still connect to the origin directly until it expires or you revoke it, as
[Revoke a leaked client certificate][plugin-revoke] in the plugin README
describes. With `aopctl`:

1. Note the leaked leaf's ID and fingerprint, which `aopctl leaf status`
   prints.
2. Issue a new leaf with `aopctl leaf issue`.
3. Add the leaked leaf's fingerprint to the plugin's
   `revokedCertFingerprints`, and keep the entry until the leaf expires.
4. Delete the leaked leaf with `aopctl leaf prune --cert-id <ID>`.

If the CA key leaks, [rotate the CA][plugin-rotate-ca].

## Development

Tools and tasks are managed with [mise](https://mise.jdx.dev). To work on
`aopctl`, clone the repository and run `mise run setup`, which installs the
tools and the pre-commit hook. `mise.toml` pins each tool to a major version,
and `mise.lock` pins the exact version and checksum for linux-x64, linux-arm64
and macos-arm64. mise skips tool releases younger than three days, and CI
applies the same cooldown to the mise binary.

| Task                     | What it does                                                                     |
| ------------------------ | -------------------------------------------------------------------------------- |
| `mise run setup`         | Install tools and the lefthook pre-commit hook                                   |
| `mise run check`         | `format:check`, `lint` and `test`; run it before pushing                         |
| `mise run format`        | Format Go code                                                                   |
| `mise run format:check`  | Check Go formatting without changing files                                       |
| `mise run lint`          | golangci-lint, actionlint, zizmor, pinact[^1] and `goreleaser check`             |
| `mise run test`          | Unit tests                                                                       |
| `mise run build`         | Snapshot release archives for every platform, in `dist/`                         |
| `mise run build:release` | Release archives for the tag at `HEAD`, in `dist/`, as the Release workflow runs |
| `mise run pin:actions`   | Pin GitHub Actions to full commit SHAs                                           |

CI runs `lint`, `format:check`, `test` and `build` as separate jobs, so a
change that breaks a release build fails before it reaches a release.

[^1]: zizmor runs its online audits, such as `known-vulnerable-actions`, only
    when `GH_TOKEN` or `GITHUB_TOKEN` is set, as in CI, and runs offline
    otherwise. pinact always queries the GitHub API, with the token when one is
    set.

The pre-commit hook (`lefthook.yml`) checks staged files offline: Go
formatting, golangci-lint when Go or lint config changes, `goreleaser check`
when `.goreleaser.yaml` changes, and actionlint, pinact and zizmor when
workflow or `.github` YAML changes. It reads the working tree, and it skips
itself without failing when `lefthook` or `mise` is not on the `PATH` of the
program running `git commit`, so CI stays authoritative. pinact's release-age
check needs the GitHub API and runs only in CI.

### Dependency updates

Dependabot updates GitHub Actions weekly with a three-day cooldown, and
`lint:pinact` rejects action pins younger than three days. To update tools,
run `mise upgrade` (which respects the cooldown), then
`mise lock --platform linux-x64,linux-arm64,macos-arm64`.

For an urgent security fix inside the cooldown window, override it for that
one change, for example `MISE_MINIMUM_RELEASE_AGE=0 mise upgrade <tool>`, and
say so in the pull request.

### Releases

[release-please](https://github.com/googleapis/release-please) maintains a
release pull request from the
[Conventional Commits](https://www.conventionalcommits.org) on `main`,
configured in `.github/release-please-config.json`. The first release is
`v0.1.0`. Before 1.0.0, breaking changes bump the minor version, and `feat`
and `fix` commits bump the patch version.

Releases are published only once their assets are attached, so they work with
GitHub's immutable releases, whose assets cannot change after publishing:

1. Merging the release pull request runs the Release Please job, last in CI
   and only after every other job passes on a push to `main` or a
   `release-X.Y.x` maintenance branch. It creates the tag (`vX.Y.Z`) and a
   draft GitHub release with the changelog.
2. The same job starts the Release workflow (`.github/workflows/release.yml`)
   for the tag, on the branch it released from.
3. The Release workflow checks that it runs on `main` or a `release-*.x`
   branch and that the release is still a draft. It builds the archives and
   checksums file from the tag with GoReleaser, and uploads them to the draft.
4. It then publishes the release. Releases from `main` become the latest
   release; releases from a maintenance branch do not.

The tag exists from step 1, so `go install github.com/krystal/aopctl@latest`
can install a version before its release is published. Publishing uses the
Release workflow's `GITHUB_TOKEN`, so it does not start workflows that listen
for published releases.

If the Release workflow fails, the release stays a draft. Re-run the failed
run, which keeps its inputs and replaces any assets it already uploaded. If
the workflow never started, run it from the branch the release was cut from:

```sh
gh workflow run release.yml --repo krystal/aopctl --ref main -f tag=v0.1.0
```

For a maintenance release, use `--ref release-X.Y.x`: the branch decides
whether the release becomes the latest release. Do not publish a draft by
hand: with immutable releases on, a release published without its assets can
never get them.

### Release setup

The Release Please job runs in the `release` environment and authenticates as
a GitHub App, so its release pull requests trigger CI. It also starts the
Release workflow as the App. Releases depend on this repository
configuration, which only maintainers can change:

- a GitHub App installed on this repository with read and write access to
  actions, contents, issues and pull requests;
- a `release` environment with a deployment branch policy that allows only
  `main` and `release-*.x`, the App's client ID in the
  `RELEASE_PLEASE_GITHUB_CLIENT_ID` variable, and the App's private key, as
  PEM rather than Base64, in the `RELEASE_PLEASE_GITHUB_APP_PRIVATE_KEY`
  secret; and
- immutable releases turned on in the repository settings, or with
  `gh api --method PUT repos/krystal/aopctl/immutable-releases`.

## License

[MIT](LICENSE)
