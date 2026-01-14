#!/bin/bash
set -e

# Vouch Protocol Release Helper
# Usage: ./scripts/release.sh X.Y.Z

VERSION=$1

if [ -z "$VERSION" ]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 1.4.1"
    exit 1
fi

echo "🚀 Preparing release for Vouch Protocol v$VERSION..."

# check if we are on main branch
BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [ "$BRANCH" != "main" ]; then
    echo "⚠️  You are not on main branch. Please switch to main."
    exit 1
fi

# Update pyproject.toml (simple sed replacement for example)
# In production, use a proper TOML parser or bumpver
echo "📝 Updating pyproject.toml..."
sed -i "s/version = \"[0-9.]*\"/version = \"$VERSION\"/" pyproject.toml

echo "✅ Updated version to $VERSION"
echo "👉 Now run:"
echo "   git add pyproject.toml"
echo "   git commit -m \"chore: bump version to $VERSION\""
echo "   git tag -a v$VERSION -m \"Release v$VERSION\""
echo "   git push origin main --tags"
echo "   python -m build"
echo "   twine upload dist/*"
