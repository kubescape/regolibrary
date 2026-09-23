# Release Procedure for RegoLibrary

This document outlines the release process for `kubescape/regolibrary`.

## Overview

Releases in `regolibrary` follow semantic versioning (`v2.0.X`) with an automated two-stage release candidate workflow managed by [`.github/workflows/create-release-v2.yaml`](.github/workflows/create-release-v2.yaml).

Releases are triggered by pushing a **release candidate tag** (e.g., `v2.0.37-rc.0`). The CI pipeline validates and tests the release, automatically creates and pushes the final tag (e.g., `v2.0.37`), updates the rolling `v2` tag, signs artifacts, and publishes the GitHub release.

---

## Step-by-Step Procedure

### 1. Ensure `master` is Up to Date

Make sure your local repository is on `master` and synchronized with `origin`:

```bash
git checkout master
git pull origin master
```

### 2. Fetch Existing Tags

> [!NOTE]
> The rolling tag `v2` is force-pushed on every release. You must pass `--force` to `git fetch` to avoid tag clobber errors.

```bash
git fetch origin --tags --force
```

### 3. Determine Next Version

Inspect recent tags to identify the latest version:

```bash
git tag -l "v2.0.*" --sort=-v:refname | head -n 10
```

Determine the next version number. If `v2.0.36` is the latest, the target release will be `v2.0.37`.

Review commits included since the last release:

```bash
git log --oneline v2.0.36..HEAD
```

### 4. Create and Push Release Candidate Tag

Create an annotated tag with the `-rc.0` suffix and push it to `origin`:

```bash
git tag -a v2.0.37-rc.0 -m "v2.0.37-rc.0"
git push origin v2.0.37-rc.0
```

### 5. Monitor GitHub Actions Workflow

Pushing `v*.*.*-rc.*` triggers the **Create and Publish Tags with Testing and Artifact Handling** workflow:

```bash
gh run list --workflow create-release-v2.yaml -L 1
gh run watch <RUN_ID>
```

#### What the workflow does automatically:
1. **`test_pr_checks`**: Runs Go basic tests on `gitregostore/...`.
2. **`build-and-rego-test`**: Tests Rego rules via OPA, generates subsection IDs, validates control IDs, exports release artifacts (`release/`), and generates SHA-256 checksums.
3. **`ks-and-rego-test`**: Runs end-to-end tests with Kubescape CLI against the newly built artifacts.
4. **`create-new-tag-and-release`**:
   - Derives `v2.0.37` from `v2.0.37-rc.0` by stripping `-rc.0`.
   - Creates and pushes git tag `v2.0.37`.
   - Force-pushes rolling short tag `v2`.
   - Signs `release/checksums.txt` using Cosign.
   - Publishes/updates the `v2` GitHub Release.
   - Creates the immutable `v2.0.37` GitHub Release with release artifacts attached.
5. **`update-documentation`**: Updates Readme/controls documentation.

### 6. Verify Release

Once the workflow finishes, verify that the release and tags are published:

```bash
gh release view v2.0.37
```
