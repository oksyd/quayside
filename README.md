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
quayside image copy docker.io/library/nginx:latest \
  registry.example.com/team/nginx:latest
```

All image platforms are copied by default. Optional flags:

- `--platform linux/amd64`: copy one platform.
- `--dry-run`: preview changes.
- `--overwrite`: replace a different destination manifest.
- `--no-progress`: hide progress bars.

OCI artifacts such as Trivy databases can also be copied. Associated signatures and SBOMs are not copied automatically.

## Inspect images

```bash
quayside tag ls registry.example.com/team/nginx
quayside image inspect registry.example.com/team/nginx:latest
quayside image digest registry.example.com/team/nginx:latest
quayside manifest get registry.example.com/team/nginx:latest --raw
```

`image copy` automatically reuses matching blobs from Docker's current context when available.
Missing content is downloaded from the source registry; the original digests and platform selection are preserved.
Docker stores without original registry blobs fall back to remote downloads.

Build a multi-platform index from existing single-platform images:

```bash
quayside index create registry.example.com/team/app:latest \
  --from registry.example.com/team/app:amd64 \
  --from registry.example.com/team/app:arm64
```

Platforms are detected from each source image. Use `--json` for machine-readable output.

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

## Shell completion

```bash
quayside completion install bash
```

Replace `bash` with your shell. Run `quayside --help` or `quayside <command> --help` for more commands and options.
