## [Unreleased]

### Changed

- `image copy` and `image pull` now select the local container platform by default (Linux containers on macOS). Use `--all` to preserve all platforms and indexed attestations, or `--platform` to select another platform. Platformless OCI artifacts remain intact.
- Show the selected platform before transfer. `--include-attestations` also accepts the default local platform.
- Identify rejected manifests by digest and type, with guidance for destinations that reject build attestations. Token-service failures retain separate diagnostics.

## [0.1.12] - 2026-10-10

### 🐛 Bug Fixes

- Improve registry authentication failure diagnostics
## [0.1.11] - 2026-09-30

### 🚀 Features

- Add persistent hierarchical progress for image transfers

### ⚙️ Miscellaneous Tasks

- Release quayside version 0.1.11
## [0.1.10] - 2026-09-29

### 🚀 Features

- Support OCI referrers and resumable image transfers

### ⚙️ Miscellaneous Tasks

- Release quayside version 0.1.10
## [0.1.9] - 2026-09-29

### 🚀 Features

- Add Compose-style progress with per-blob outcomes and elapsed time

### ⚙️ Miscellaneous Tasks

- Release quayside version 0.1.9
## [0.1.8] - 2026-09-24

### 🚀 Features

- Reuse local Docker blobs during image copy

### ⚙️ Miscellaneous Tasks

- Release quayside version 0.1.8
## [0.1.7] - 2026-09-22

### 🚀 Features

- Support pushing local Docker images and save archives

### ⚙️ Miscellaneous Tasks

- Release quayside version 0.1.7
## [0.1.6] - 2026-09-20

### ⚡ Performance

- Parallelize registry transfers and manifest processing

### ⚙️ Miscellaneous Tasks

- Release quayside version 0.1.6
## [0.1.5] - 2026-09-20

### 🐛 Bug Fixes

- Ci

### ⚙️ Miscellaneous Tasks

- Release quayside version 0.1.5
## [0.1.4] - 2026-09-20

### 🐛 Bug Fixes

- Ci

### ⚙️ Miscellaneous Tasks

- Release quayside version 0.1.4
## [0.1.3] - 2026-09-20

### 🐛 Bug Fixes

- Ci

### ⚙️ Miscellaneous Tasks

- Release quayside version 0.1.3
## [0.1.2] - 2026-09-20

### ⚙️ Miscellaneous Tasks

- Init commit
- Release quayside version 0.1.2
