# aopctl

`aopctl` is a command-line tool for Cloudflare's per-hostname
[Authenticated Origin Pulls](https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/set-up/per-hostname/)
(AOP). It creates a dedicated AOP client CA, issues leaf certificates from it,
uploads them to Cloudflare, points hostnames at them, and deletes the ones you
no longer use. It also manages [zone-level AOP](#zone-level-aop) certificates
from the same CA.

It covers the Cloudflare steps of [Set up Cloudflare][plugin-setup] for
[traefik-plugin-cloudflare-origin][plugin], the Traefik plugin that verifies
these certificates at the origin. It does not manage the zone's global AOP
setting, DNS, other zone settings or Traefik configuration. The one exception
is `aopctl ca show --secret`, which prints the CA Secret from the plugin's
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
[cf-zone-aop]: https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/set-up/zone-level/
[cf-manage-certs]: https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/set-up/manage-certificates/

## Install

Prebuilt binaries cover Linux and macOS on amd64 and arm64. There are no
Windows builds: `aopctl` asks for confirmation through `/dev/tty`.

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

`go install` builds `aopctl` from source and needs Go 1.26 or later:

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
version Go records for it, or `(devel)`. `aopctl --version` and `aopctl -v`
print the same.

### Shell completion

`aopctl completion <shell>` prints a completion script for `bash`, `zsh`,
`fish` or `powershell`, and `aopctl completion <shell> --help` explains how to
load it. For example:

```sh
# bash, with the bash-completion package installed
aopctl completion bash > ~/.local/share/bash-completion/completions/aopctl
# zsh, into a directory on your fpath
aopctl completion zsh > "${fpath[1]}/_aopctl"
# fish
aopctl completion fish > ~/.config/fish/completions/aopctl.fish
```

Completion covers commands, flags, the `--key-type` values and, for
`--hostname`, the entries of `AOP_HOSTNAMES` when it is set. It never calls
the Cloudflare API, so it needs no token.

## Configure

`aopctl` reads its configuration from environment variables, so any way of
setting them works. It contains no 1Password code, but the examples here use
1Password's `op run`: keep `op://` references in an env file, and run each
`hostname` and `zone` command through `op run --env-file`.

```sh
# aop.env
AOP_CA_CERT=op://<vault>/<item>/ca_cert
AOP_CA_KEY=op://<vault>/<item>/ca_key
CLOUDFLARE_API_TOKEN=op://<vault>/<token item>/credential
CLOUDFLARE_ZONE_ID=<zone ID>
AOP_HOSTNAMES=app.example.com,admin.example.com
```

```sh
op run --env-file aop.env -- aopctl hostname status
```

| Variable               | Used by                                                                               |
| ---------------------- | ------------------------------------------------------------------------------------- |
| `AOP_CA_CERT`          | every `hostname` and `zone` command; optional for `hostname status` and `zone status` |
| `AOP_CA_KEY`           | `hostname issue` and `zone issue`, as a PKCS#8 PEM                                    |
| `CLOUDFLARE_API_TOKEN` | every `hostname` and `zone` command                                                   |
| `CLOUDFLARE_ZONE_ID`   | every `hostname` and `zone` command                                                   |
| `AOP_HOSTNAMES`        | every `hostname` command, comma- or whitespace-separated                              |

`AOP_HOSTNAMES` must list every hostname this CA serves in the zone.
Cloudflare has no API that lists all hostname associations, so `aopctl` only
sees the hostnames you list. `--hostname` flags replace the variable. Repeat
the flag or give it a comma-separated list, as in
`--hostname app.example.com,admin.example.com`.
A certificate can serve at most 100 hostnames.

Create the API token with the **Zone > SSL and Certificates > Edit**
permission for the zone. `hostname status` and `zone status` only need Read,
but every other `hostname` and `zone` command writes. Cloudflare's API
reference lists the same permission, as SSL and Certificates Read or Write, for
the zone-level certificate and setting endpoints. Account-owned tokens work.
They fail Cloudflare's token verify endpoint, which `aopctl` does not use.

## Commands

| Command                                  | What it does                                                                    |
| ---------------------------------------- | ------------------------------------------------------------------------------- |
| `aopctl ca create`                       | Create a CA and print a 1Password item template                                 |
| `aopctl ca show`                         | Describe the CA certificate on stdin, or print it as a Kubernetes Secret        |
| `aopctl hostname issue`                  | Issue a leaf, upload it and point the listed hostnames at it                    |
| `aopctl hostname associate --cert-id ID` | Point the listed hostnames at an existing leaf, to resume or roll back an issue |
| `aopctl hostname status`                 | List the zone's hostname certificates and the listed hostnames' associations    |
| `aopctl hostname prune --cert-id ID...`  | Delete the named certificates after checking that no listed hostname uses them  |
| `aopctl zone issue`                      | Issue a zone-level leaf, upload it and wait for it to become active             |
| `aopctl zone enable`                     | Turn on zone-level AOP for the newest active zone-level certificate             |
| `aopctl zone status`                     | Show the zone-level AOP setting and certificates, and the one in use            |
| `aopctl zone prune --cert-id ID...`      | Delete the named zone-level certificates, keeping one active while enabled      |
| `aopctl version`                         | Print the `aopctl` version                                                      |

Run `aopctl <command> --help` for each command's flags. Flags take two
dashes, as in `--dry-run`. The only short forms are `-h` for `--help`, `-v`
for `--version` and `-n` for `--dry-run`. `aopctl` exits with 0 on success, 1
on errors and 2 on usage errors, such as an unknown command or flag.

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

`aopctl hostname issue` issues an EC P-256 leaf (`--key-type rsa-3072` for RSA)
for client authentication, valid for 365 days (`--days`). Before it writes
anything, it checks that the zone has a free certificate slot (Cloudflare
allows 10) and reads each hostname's association. It refuses a hostname whose
association is disabled, since someone turned AOP off for it on purpose. It
then uploads the leaf, waits for Cloudflare to report it `active`, points all
listed hostnames at it in one request, and waits until each association is
`active`. `--dry-run` (`-n`) prints the plan and changes nothing. The leaf
key is only ever sent in the upload request. `hostname issue` never deletes a
certificate.

`aopctl hostname prune` deletes only the certificates named with
`--cert-id`. It refuses a certificate that is not signed by `AOP_CA_CERT` or
that a listed hostname uses, and checks the listed hostnames again just before
each delete. It shows a preview and asks for confirmation on the terminal,
through `/dev/tty` so the prompt works under `op run`, unless you pass
`--yes`. A certificate already being deleted is waited for, not deleted again.

`hostname issue`, `hostname associate` and `hostname prune` poll every 5
seconds within a total budget for the whole command, `--timeout`, which
defaults to 10 minutes. When the budget runs out, they report the last state
they saw.

## Rotate the leaf certificate

When the plugin pins the CA, rotating the leaf needs no Traefik change.

1. Preview the rotation, and check the hostnames and the certificates they
   use now:

   ```sh
   op run --env-file aop.env -- aopctl hostname issue --dry-run
   ```

2. Issue and roll out the new leaf:

   ```sh
   op run --env-file aop.env -- aopctl hostname issue
   ```

   It prints the certificates the listed hostnames no longer use, and the
   `aopctl hostname prune` command that deletes them.
3. Check the result with `aopctl hostname status`, and check that requests
   through Cloudflare still reach the backend with the client IP, for example
   in the [access log][plugin-access-logs].
4. Prune the old certificates soon, with the printed command:

   ```sh
   op run --env-file aop.env -- aopctl hostname prune --cert-id <old ID> --hostname <hostname>...
   ```

   Cloudflare's documentation says that when several certificates exist, "the
   most recently deployed certificate will be the one enabled and used". That
   conflicts with choosing a certificate per hostname, so do not keep old
   certificates around.

An `active` status in the API does not prove which certificate Cloudflare
presents to your origin. Before the first production rollout, check it
against a staging origin: pin the new leaf's fingerprint, which
`hostname issue` prints, instead of the CA's on a staging hostname. Requests
through Cloudflare then pass only when Cloudflare presents the new leaf.

To rotate the CA itself, follow [Rotate the CA][plugin-rotate-ca] in the
plugin README. `aopctl hostname associate` and `aopctl hostname prune` only
accept certificates signed by `AOP_CA_CERT`, so roll back to, or prune, the
old CA's leaves with `AOP_CA_CERT` set to the old CA.

## Recover or roll back

If `hostname issue` fails after the upload, it prints the new certificate's
ID, each hostname's original and observed association, and the commands to
continue or undo the rollout:

- To resume, run the printed
  `aopctl hostname associate --cert-id <new ID> --hostname ...` command.
- To roll back, run the printed `aopctl hostname associate` commands, one per
  certificate the hostnames used before, each listing only that certificate's
  hostnames.
- `aopctl` never voids an association, so for hostnames that had none, it
  prints the API request that voids the new one. You can also remove it in
  the Cloudflare dashboard.

  ```text
  PUT /zones/{zone}/origin_tls_client_auth/hostnames
  {"config":[{"hostname":"<hostname>","cert_id":"<new ID>","enabled":null}]}
  ```

None of these needs a free certificate slot. `hostname associate` only
accepts an `active` certificate signed by `AOP_CA_CERT`, and `--dry-run`
previews it. During a CA rotation, the hostnames' original certificates are
the old CA's, so run the rollback commands with `AOP_CA_CERT` set to the old
CA. `hostname issue` marks each command that needs this.

If the new certificate never becomes active, `hostname issue` changes no
hostname, so there is nothing to resume or roll back. It prints the
`aopctl hostname prune` command that deletes the certificate, so you can run
`hostname issue` again, and the `aopctl hostname associate` command to use if
it becomes active later.

If the upload fails without a usable response or with a server error, for
example on a timeout or an HTTP 5xx, `hostname issue` reports that the outcome
is unknown. Cloudflare may have created the certificate, so run
`aopctl hostname status` before you retry.

## If a leaf key leaks

Deleting a leaf from Cloudflare does not revoke it. Anyone with its key can
still connect to the origin directly until it expires or you revoke it, as
[Revoke a leaked client certificate][plugin-revoke] in the plugin README
describes. With `aopctl`:

1. Note the leaked leaf's ID and fingerprint, which `aopctl hostname status`
   prints.
2. Issue a new leaf with `aopctl hostname issue`.
3. Add the leaked leaf's fingerprint to the plugin's
   `revokedCertFingerprints`, and keep the entry until the leaf expires.
4. Delete the leaked leaf with `aopctl hostname prune --cert-id <ID>`.

If the CA key leaks, [rotate the CA][plugin-rotate-ca].

## Zone-level AOP

With [zone-level AOP][cf-zone-aop] enabled, Cloudflare presents one
certificate to every origin in the zone. A hostname with a per-hostname
certificate uses that one instead. Zone-level AOP has its own setting,
separate from the zone's global AOP setting, `tls_client_auth`, which uses
Cloudflare's shared certificate. `aopctl` never reads or changes the global
setting, and it never turns zone-level AOP off.

The API does not say which zone-level certificate Cloudflare uses. Cloudflare's
[certificate docs][cf-manage-certs] say that when several are `active`, "the
most recently deployed certificate will be the one enabled and used". `aopctl`
therefore treats the active certificate with the latest `uploaded_on` as the
one in use while zone-level AOP is enabled, and labels it as derived. When the
active certificates' `uploaded_on` values are missing, unreadable or equal, it
reports the certificate in use as unknown. It ignores each certificate's
`enabled` field, whose meaning Cloudflare does not document, and only shows it.

`aopctl zone issue` issues a leaf with the same flags and defaults as
`hostname issue`, uploads it and waits for it to become `active`. It never
deletes a certificate and never changes the setting. Its plan shows the new
leaf, the zone-level certificates, the setting and the certificate in use, and
`--dry-run` stops there. While zone-level AOP is enabled, the new certificate
takes over the zone as soon as it is active. So when the certificate in use is
not signed by `AOP_CA_CERT`, or is unknown, `zone issue` asks for confirmation
first, unless you pass `--yes`: origins that trust only the old CA would
reject Cloudflare's requests. Afterwards it prints the `aopctl zone prune`
commands for the previously active certificates, or the `aopctl zone enable`
command while zone-level AOP is disabled. If the new certificate never becomes
active, it prints the `aopctl zone prune` command that removes it. If the
upload outcome is unknown, run `aopctl zone status` before you retry.
Cloudflare documents no limit on zone-level certificates, so `aopctl` checks
none and reports Cloudflare's error if there is one.

`aopctl zone enable` turns zone-level AOP on. It refuses unless the zone has an
active zone-level certificate and `AOP_CA_CERT` signed the newest active one,
which Cloudflare then uses. It asks for confirmation unless you pass `--yes`,
checks the certificates again just before the change, and reads the setting
back. If the request fails without a usable response or with a server error,
or the read-back fails, it reports that zone-level AOP may now be enabled, so
run `aopctl zone status` before you retry. If zone-level AOP is already on, it
changes nothing. To turn zone-level
AOP off, use the Cloudflare dashboard or this API request:

```text
PUT /zones/{zone}/origin_tls_client_auth/settings
{"enabled":false}
```

`aopctl zone status` shows the setting and each zone-level certificate's ID,
status, subject, key type, fingerprint, expiry, `uploaded_on`, `enabled` field
and whether `AOP_CA_CERT` signed it. It marks the certificate in use and warns
when more than one certificate is active.

`aopctl zone prune` deletes only the certificates named with `--cert-id`. An ID
is a UUID, with or without dashes, in either case. Like `hostname prune`, it
refuses a certificate that is missing or not signed by `AOP_CA_CERT`, and waits
for one already being deleted. While zone-level AOP is enabled, it also refuses
to delete the last active certificate. When you name every active certificate,
it keeps the newest one, and Cloudflare uses that one afterwards, which may not
be the one it uses now. It checks the zone again just before each delete.

When `zone prune` deletes the certificate in use, it shows the one Cloudflare
falls back to: the newest remaining active certificate. It warns when
`AOP_CA_CERT` did not sign that certificate, or when it cannot tell which one
it is, because origins that trust only `AOP_CA_CERT` would then reject
Cloudflare's requests. Deleting a new certificate to fall back to an older one
is how you roll back a rotation. It asks for confirmation unless you pass
`--yes`. `--dry-run` shows the plan without deleting, and exits with 1 when
the plan refuses or keeps a named certificate.

`zone issue`, `zone enable` and `zone prune` take the same `--timeout` budget
as the `hostname` commands.

### Set up zone-level AOP

1. Issue a zone-level leaf. With zone-level AOP still disabled, Cloudflare does
   not use it yet:

   ```sh
   op run --env-file aop.env -- aopctl zone issue
   ```

2. Configure the origins to trust the CA, then turn zone-level AOP on:

   ```sh
   op run --env-file aop.env -- aopctl zone enable --dry-run
   op run --env-file aop.env -- aopctl zone enable
   ```

### Rotate the zone-level certificate

Cloudflare's [rotation steps][cf-manage-certs] are to upload the new
certificate, wait until it is `active`, then delete the previous one:

1. Preview the rotation with `aopctl zone issue --dry-run`.
2. Run `aopctl zone issue`. It prints the `aopctl zone prune` command for the
   certificates Cloudflare no longer uses.
3. Check with `aopctl zone status`, and check that requests through Cloudflare
   still reach the backend.
4. Run the printed `aopctl zone prune` command.

## Use as a subcommand

The `github.com/krystal/aopctl/cli` package is the `aopctl` command line. A
tool built with [cobra](https://github.com/spf13/cobra) can mount it as a
subcommand:

```go
root := &cobra.Command{Use: "othertool"}
root.AddCommand(cli.NewCommand(cli.Options{}))
err := root.ExecuteContext(ctx)
os.Exit(cli.ExitCode(err))
```

`othertool aopctl hostname status` then works as `aopctl hostname status`
does, with the same environment variables. The commands `aopctl` prints, such
as the rollback and prune commands, start with `othertool aopctl`. Its errors
print with an `aopctl:` prefix unless the root command sets `SilenceErrors`,
and `cli.ExitCode` maps them to `aopctl`'s exit status: 0, 1, or 2 for usage
errors. `cli.Options` can set the version and supply the environment variables
from elsewhere than the process environment.

## Use as a Go library

The `aopctl` command is a thin wrapper around the
`github.com/krystal/aopctl/aopctl` package, which other tools can embed. It has
the same workflows and safety checks, but reads no environment variables,
prints nothing and never prompts:

```go
client, err := aopctl.NewClient(apiToken, zoneID, aopctl.Options{})
// handle err
plan, err := client.PlanHostnameIssue(ctx, aopctl.HostnameIssueRequest{
	CACert: caCert, CAKey: caKey,
	CommonName: "my AOP client", KeyType: aopctl.KeyTypeECP256, Days: 365,
	Hostnames: []string{"app.example.com"},
})
// handle err, then show the plan or ask for confirmation
result, err := plan.Apply(ctx)
```

Each workflow that changes Cloudflare has a `Plan` method that only reads, and
an `Apply` that runs once. A request's `Progress` callback receives events
during `Apply`, and errors such as `*aopctl.UploadUnknownError`,
`*aopctl.HostnameRolloutError` and `*aopctl.ZoneRolloutError` carry what you
need to resume or roll back. `Hostname…` workflows manage per-hostname AOP, and
`Zone…` workflows manage zone-level AOP. See the
[package documentation](https://pkg.go.dev/github.com/krystal/aopctl/aopctl).

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

Dependabot updates GitHub Actions and Go modules weekly with a three-day
cooldown, and `lint:pinact` rejects action pins younger than three days. To
update tools, run `mise upgrade` (which respects the cooldown), then
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
