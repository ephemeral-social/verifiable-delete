#!/usr/bin/env bash
set -euo pipefail

# Sync ephemeral_verifiable_delete/ to the public repo: ephemeral-social/verifiable-delete
#
# Clones the public repo, syncs files from the monorepo subfolder,
# and pushes an incremental commit (preserving public repo history).
#
# Usage:
#   ./scripts/sync-to-public.sh                  # dry run (default)
#   ./scripts/sync-to-public.sh --push           # actually push
#   ./scripts/sync-to-public.sh --push -m "feat: add core library"

PUBLIC_REPO="https://github.com/ephemeral-social/verifiable-delete.git"
BRANCH="main"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SOURCE_DIR="$(dirname "$SCRIPT_DIR")"  # ephemeral_verifiable_delete/

DRY_RUN=true
COMMIT_MSG="Sync from monorepo"

while [[ $# -gt 0 ]]; do
  case $1 in
    --push) DRY_RUN=false; shift ;;
    --message|-m) COMMIT_MSG="$2"; shift 2 ;;
    --help|-h)
      echo "Usage: $0 [--push] [--message \"commit message\"]"
      echo "  --push     Actually push (default is dry run)"
      echo "  --message  Custom commit message (default: 'Sync from monorepo')"
      exit 0
      ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

# Sanity checks
if [[ ! -f "$SOURCE_DIR/package.json" ]]; then
  echo "ERROR: Must run from ephemeral_verifiable_delete/ or its scripts/ dir"
  exit 1
fi

if ! gh auth status &>/dev/null; then
  echo "ERROR: Not authenticated with GitHub CLI. Run: gh auth login"
  exit 1
fi

echo "=== Syncing to public repo ==="
echo "Source:  $SOURCE_DIR"
echo "Target:  $PUBLIC_REPO ($BRANCH)"
echo "Mode:    $(if $DRY_RUN; then echo 'DRY RUN'; else echo 'LIVE PUSH'; fi)"
echo ""

# Create temp directory
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# Clone existing public repo to preserve history
echo "Cloning public repo..."
if git ls-remote --exit-code "$PUBLIC_REPO" refs/heads/"$BRANCH" &>/dev/null; then
  git clone -q --single-branch --branch "$BRANCH" "$PUBLIC_REPO" "$TMPDIR"
  cd "$TMPDIR"
  # Remove all tracked files (except .git) so we get a clean diff
  git rm -rq --ignore-unmatch . 2>/dev/null || true
else
  # Empty repo - initialize fresh
  echo "(Public repo is empty, creating initial commit)"
  cd "$TMPDIR"
  git init -q
  git branch -M "$BRANCH"
  git remote add origin "$PUBLIC_REPO"
fi

# Copy files from monorepo (respecting exclusions)
rsync -a \
  --exclude='.git' \
  --exclude='node_modules' \
  --exclude='.DS_Store' \
  --exclude='.env' \
  --exclude='.env.*' \
  --exclude='!.env.example' \
  --exclude='.dev.vars' \
  --exclude='dist' \
  --exclude='coverage' \
  --exclude='.wrangler' \
  --exclude='CLAUDE.md' \
  --exclude='.claude' \
  "$SOURCE_DIR/" "$TMPDIR/"

# Quick secrets check - abort if any obvious secrets slip through
if grep -rq "sk_live_[a-zA-Z0-9]\{20,\}\|sk_test_[a-zA-Z0-9]\{20,\}\|JWT_SECRET=\|TWILIO_AUTH=\|PRIVATE_KEY=['\"]" --include="*.ts" --include="*.js" --include="*.json" --include="*.toml" "$TMPDIR/" 2>/dev/null; then
  echo "ERROR: Potential secrets detected! Aborting."
  echo "Run a manual review before syncing."
  exit 1
fi

# Stage all changes
git add -A

# Check if there are actual changes
if git diff --cached --quiet; then
  echo "No changes to sync. Public repo is already up to date."
  exit 0
fi

# Show summary
CHANGED=$(git diff --cached --stat | tail -1)
echo "Changes: $CHANGED"
echo ""

git commit -q -m "$COMMIT_MSG"

if $DRY_RUN; then
  echo "DRY RUN complete. Changes above would be pushed."
  echo "Run with --push to actually push to $PUBLIC_REPO"
else
  git push origin "$BRANCH"
  echo "Pushed to $PUBLIC_REPO ($BRANCH)"
fi
