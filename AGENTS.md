# Agent Guidelines for RegoLibrary

## Release Procedure

To trigger a release of `regolibrary`:

1. Sync local master:
   ```bash
   git checkout master && git pull origin master
   git fetch origin --tags --force
   ```
2. Determine next version from latest tags:
   ```bash
   git tag -l "v2.0.*" --sort=-v:refname | head -n 5
   ```
3. Tag and push a release candidate tag (e.g. `v2.0.37-rc.0`):
   ```bash
   git tag -a v<VERSION>-rc.0 -m "v<VERSION>-rc.0"
   git push origin v<VERSION>-rc.0
   ```
4. The CI pipeline [`.github/workflows/create-release-v2.yaml`](.github/workflows/create-release-v2.yaml) automatically:
   - Validates, tests Regos, and runs Kubescape CLI e2e tests
   - Automatically derives, tags, and pushes `v<VERSION>`
   - Force-pushes rolling tag `v2`
   - Signs checksums and publishes the GitHub release

Detailed documentation: [RELEASE.md](RELEASE.md)
