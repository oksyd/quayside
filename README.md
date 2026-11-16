# Quayside

Copy and inspect OCI images and artifacts without a Docker daemon.

## Install

Download the archive for your platform from this repository's GitHub Releases, extract it, and place `quayside` in a directory on your `PATH`.

Supported platforms: Linux x86_64, Linux ARM64, and macOS Apple Silicon.

## Log in

```bash
quayside login registry.example.com --username alice --repository team/nginx
```

Enter your password or token when prompted. For automation, use `--password-stdin`.

## Copy images

```bash
quayside image copy nginx:latest \
  registry.example.com/team/nginx:latest
```

Source names default to Docker Hub: `nginx:latest` resolves to `docker.io/library/nginx:latest`, and `apache/skywalking-banyandb:0.11.0` to `docker.io/apache/skywalking-banyandb:0.11.0`.

Copy the highest numeric `x.y.z` version, keeping its exact tag at the destination:

```bash
quayside image copy nginx registry.example.com/team/nginx --latest
quayside image copy nginx registry.example.com/team/nginx --latest --variant alpine
```

With `--latest`, the source must have no tag or digest. Versions allow an optional `v` prefix; aliases and prereleases are excluded by default. `--variant` matches an exact suffix. An explicit destination tag is preserved. Selection and tag resolution use the source registry; the transfer retains the resolved digest even if the tag changes. No matching version is an error.

For daily updates, add one command per task to your crontab (use the same user that logged in):

```cron
0 3 * * * /usr/local/bin/quayside image copy nginx registry.example.com/team/nginx --latest --no-progress >> /var/log/quayside-nginx.log 2>&1
```

Use your installed binary path and a writable log path. Repeated runs skip existing content. New versions get new destination tags; replacing different content under an existing tag still requires `--overwrite`.

Copy and pull select the local container platform by default: `linux/amd64` on Linux x86_64, or `linux/arm64` on Linux ARM64 and macOS Apple Silicon. The selected platform is displayed before transfer; a missing match is an error. Optional flags:

- `--platform linux/amd64`: select a different platform explicitly.
- `--all`: preserve all platforms and indexed attestations.
- `--include-attestations`: retain that platform's indexed attestations in a new OCI index.
- `--referrers all`: discover and recursively copy associated signatures and SBOMs.
- `--resume`: retain partial downloads and upload sessions for the next run.
- `--no-mirrors`: read directly from Docker Hub, ignoring configured registry mirrors.
- `--dry-run`: preview changes.
- `--overwrite`: replace a different destination manifest.
- `--no-progress`: hide progress bars.

OCI artifacts such as Trivy databases are copied intact without platform filtering. Single-platform transfers omit indexed attestations unless `--include-attestations` is set. This flag also works with the default local platform; it creates a new index digest while preserving child manifest bytes. Independent referrers are discovered only with `--referrers all`; signatures are not verified.

If the destination rejects build attestations, use the default platform or `--platform` without `--include-attestations` or `--referrers all`. Preserving attestations with `--all` or `--include-attestations` requires destination support for those manifests.

`image copy` automatically reuses matching blobs from Docker's current context when available.
Missing content is downloaded from the source registry; the original digests and platform selection are preserved.
Cache preparation has a two-second budget before falling back to downloads. Set `transfer.docker_cache_timeout` to adjust it, or `"0s"` to disable reuse.

## Inspect images

Find the highest release version without opening Docker Hub:

```bash
quayside tag latest nginx
quayside tag latest nginx --variant alpine
```

The result is a full image reference, ready for `image copy`. By default, only `x.y.z` tags (optional `v` prefix) are compared numerically; `--variant` selects an exact suffix. This finds the highest version, not the newest push or the publisher's stable channel. No matching version is an error. Use a full repository name for other registries.

```bash
quayside tag ls registry.example.com/team/nginx
quayside image inspect registry.example.com/team/nginx:latest
quayside image digest registry.example.com/team/nginx:latest
quayside manifest get registry.example.com/team/nginx:latest --raw
```

Build a multi-platform index from existing single-platform images:

```bash
quayside index create registry.example.com/team/app:latest \
  --from registry.example.com/team/app:amd64 \
  --from registry.example.com/team/app:arm64
```

Platforms are detected from each source image; source images are kept. Use `--json` for machine-readable output, including referrer transfer status (`not-copied`, `planned`, or `copied`).

## Transfer offline

Export an OCI archive, move it to the destination machine, then upload it:

```bash
quayside image pull docker.io/library/nginx:latest \
  --output nginx.oci.tar --format oci-archive

quayside image push nginx.oci.tar registry.example.com/team/nginx:latest
```

Push an image already stored in Docker (requires the Docker CLI and daemon):

```bash
quayside image push --docker nginx:latest registry.example.com/team/nginx:latest
```

Or push an uncompressed `docker save` archive without Docker installed:

```bash
quayside image push nginx.docker.tar registry.example.com/team/nginx:latest
```

Only locally stored platforms are pushed. Use `--ref <exact-tag>` to select an image from a multi-image Docker archive.
Legacy Docker archives are converted to OCI; the original registry manifest digest is not preserved.

`image pull` also accepts `--referrers all`, `--include-attestations`, and `--resume`. Associated artifacts exported with `--referrers all` are preserved by `image push`.

Repeat the same `copy` or `pull` command with `--resume` after an interruption. Cached bytes are verified; expired upload sessions restart automatically. Resume data is private to your user, stored under the system cache directory in `quayside/transfers`, and removed after success. Set `transfer.resume_dir` to choose another directory. Interrupted caches can be deleted when no transfer is running. `transfer.max_temp_size` bounds each operation's payload storage, including resume data; resumable exports require room for both cached blobs and the output staging. Resume mode uses its own cache instead of exporting Docker's local cache.

Copy, pull, and push show an image summary with per-blob progress through completion. Rows stay in order, with extra rows folded to fit the terminal; completed and failed results remain visible. Use `--no-progress` to hide it.

Color-capable terminals use cyan activity icons and green completion marks, with muted waiting and existing layers. Failures are red; interruptions and warning labels are yellow. `--no-color` or `NO_COLOR` disables colors while keeping progress. JSON and redirected stderr remain uncolored.

## Configuration

No configuration file is required. See [config.example.toml](config.example.toml) for optional settings; use `--config <path>` to select a file.

Configure a private CA:

```bash
quayside registry set registry.example.com --ca-file /path/to/ca.pem
```

Set a proxy:

```bash
export HTTPS_PROXY=http://127.0.0.1:7890
export NO_PROXY=localhost,127.0.0.1,.example.com
```

Docker `daemon.json` proxy settings are used as defaults when environment variables are absent.

For Docker Hub sources, `image copy` and `image pull` also use that file's `registry-mirrors` in order, then Docker Hub. Each mirror is announced once on stderr with its configuration source. Missing content, denied access and network failures try the next source; certificate, content-integrity and configuration errors stop the operation. Quiet and JSON modes suppress these notices.

Configured mirrors are trusted to resolve tags and may serve older content. `image copy --latest` resolves tags at the origin and uses mirrors only for content identified by digest; use `--no-mirrors` to bypass mirrors entirely. Tag queries, inspection, referrer discovery and destination writes always use their original registries. Downloads retain digest verification and resume support; mirror credentials are isolated from Docker Hub credentials. Mirror URLs must be HTTP(S) origins without paths or embedded credentials; an explicit HTTP URL uses unencrypted transport. Other Docker settings, including `insecure-registries`, remain ignored.

Delegated uploads and missing blobs advertised through descriptor URLs support HTTPS content hosts. Registry credentials stay on the registry origin. Private content hosts can use their own `ca_file`; HTTP delegation requires both the registry and the content host to be explicitly configured with `plain_http`. HTTPS transfers never downgrade to HTTP.

## Shell completion

```bash
quayside completion install bash
```

Replace `bash` with your shell. Run `quayside --help` or `quayside <command> --help` for more commands and options.
