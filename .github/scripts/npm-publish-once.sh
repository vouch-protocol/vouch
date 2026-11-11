#!/usr/bin/env bash
# Publish the npm package in the current directory, once.
#
# A version that is already on the registry is skipped. Any other publish
# error fails the step, and after a publish the step waits until the registry
# lists the new version, so a green run means the version is live.
set -euo pipefail

name=$(node -p "require('./package.json').name")
version=$(node -p "require('./package.json').version")

listed() {
  [ "$(npm view "${name}@${version}" version 2>/dev/null || true)" = "${version}" ]
}

if listed; then
  echo "${name}@${version} is already on npm, skipping"
  exit 0
fi

npm publish --access public --provenance

for _ in $(seq 1 18); do
  if listed; then
    echo "${name}@${version} is live on npm"
    exit 0
  fi
  sleep 10
done
echo "::error::${name}@${version} was published but the registry does not list it after 3 minutes"
exit 1
