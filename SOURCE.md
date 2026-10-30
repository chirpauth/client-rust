# Source of truth

This repo's source of truth is **amber-git** (`https://amber-git.stackwell.tech/client-rust.git`), not
GitHub. `origin` points there; GitHub (`chirpauth/client-rust`) is a read-only mirror
that amber-git updates on every accepted push, so GitHub Actions keep running.

- Push branches to `origin` only. The mirror creates the GitHub branch within
  seconds; open the PR on GitHub after it appears.
- Land with `ops/scripts/land_amber.py chirpauth/client-rust <sha>`, never the GitHub
  merge button: the next mirror push of `main` overwrites a GitHub-side merge.
- Never push to `github`. A branch pushed there exists only on GitHub.
