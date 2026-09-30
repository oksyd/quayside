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

All image platforms are copied by default. Optional flags:

- `--platform linux/amd64`: copy one platform.
- `--include-attestations`: retain that platform's indexed attestations in a new OCI index.
- `--referrers all`: discover and recursively copy associated signatures and SBOMs.
- `--resume`: retain partial downloads and upload sessions for the next run.
- `--dry-run`: preview changes.
- `--overwrite`: replace a different destination manifest.
- `--no-progress`: hide progress bars.

OCI artifacts such as Trivy databases can also be copied. Attestations included in the selected image index are preserved, with subject associations registered at the destination. Independent referrers are discovered only with `--referrers all`; signatures are not verified. Filtering platforms with `--include-attestations` creates a new index digest; child manifests remain unchanged.

`image copy` automatically reuses matching blobs from Docker's current context when available.
Missing content is downloaded from the source registry; the original digests and platform selection are preserved.
Cache preparation has a two-second budget before falling back to downloads. Set `transfer.docker_cache_timeout` to adjust it, or `"0s"` to disable reuse.

## Inspect images

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

Delegated uploads and missing blobs advertised through descriptor URLs support HTTPS content hosts. Registry credentials stay on the registry origin. Private content hosts can use their own `ca_file`; HTTP delegation requires both the registry and the content host to be explicitly configured with `plain_http`. HTTPS transfers never downgrade to HTTP.

## Shell completion

```bash
quayside completion install bash
```

Replace `bash` with your shell. Run `quayside --help` or `quayside <command> --help` for more commands and options.
