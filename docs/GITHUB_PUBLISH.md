# Publish LocalPwn v1.0 candidate to GitHub

Your repository is **https://github.com/AhmeadAlhamdani/LocalPwn**. Older releases are nested under `LocalPwn/` within the Git repository. For v1.0 we recommend **flattening that folder into the repository root** so GitHub Actions runs and Kali installation uses a single path.

## Recommended: publish a flat-root repository in a release branch

On Kali, assuming the ZIP was extracted to `~/Downloads/LocalPwn-v1.0-rc1/LocalPwn/`:

```bash
sudo apt update && sudo apt install -y git rsync gh
cd ~/LocalPwn
# Outer Git checkout; preserve its .git/ directory.
git status
git pull --ff-only origin main
git switch -c release/v1.0-rc1
# Remove the tracked old nested source tree (NOT the outer .git directory).
git rm -r LocalPwn
# Copy the new v1 files directly into the Git repository root.
rsync -av --exclude='.git/' --exclude='.venv/' --exclude='.localpwn/' \
  ~/Downloads/LocalPwn-v1.0-rc1/LocalPwn/ ./
git status
# Read the diff and verify no credentials or unwanted deletions.
git diff --check
git add -A
git diff --cached --stat
git commit -m "LocalPwn v1.0 release candidate and root layout"
git push -u origin release/v1.0-rc1
```

Open GitHub → **Pull requests → New pull request** for `release/v1.0-rc1` into `main`. Confirm automated tests and review changed files. The `.github/workflows/ci.yml` file is now at the Git repository root so GitHub Actions can detect it.

After merging:

```bash
cd ~/LocalPwn
git switch main
git pull --ff-only origin main
bash scripts/express-install.sh --test
.venv/bin/localpwn doctor
.venv/bin/localpwn web
```

Tag and optionally publish a prerelease after testing:

```bash
git tag -a v1.0.0-rc1 -m 'LocalPwn v1.0 release candidate'
git push origin v1.0.0-rc1
gh release create v1.0.0-rc1 --prerelease --title 'LocalPwn v1.0 RC1' --notes-file CHANGELOG.md
```

**Do not tag v1.0.0 stable or claim production approval until security/deployment acceptance gates pass.**

## GitHub browser-only upload

Open the repository root. Use **Add file → Upload files** to add new files, or open individual existing files and use the pencil editor to replace them. Uploading an identical path may not overwrite reliably depending on the browser workflow. CLI Git is strongly preferred because it preserves history and nested structure.

## Why flatten the Git tree?

Older releases were uploaded into an extra `LocalPwn/` directory. Putting `README.md`, `src/`, `scripts`, `pyproject.toml` and `.github/` at the repository root provides standard `git clone` installation and functional GitHub Actions. The commands above never remove the outer `.git` directory.
