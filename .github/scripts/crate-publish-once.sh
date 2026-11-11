#!/usr/bin/env bash
# Publish the crate in the current directory to crates.io, once.
#
# A version that is already on crates.io is skipped. Any other publish error
# fails the step. Needs CARGO_REGISTRY_TOKEN in the environment.
set -euo pipefail

read -r name version < <(cargo metadata --no-deps --format-version 1 --manifest-path Cargo.toml \
  | python3 -c 'import json,sys,os; m=json.load(sys.stdin); p=[p for p in m["packages"] if os.path.samefile(os.path.dirname(p["manifest_path"]), ".")][0]; print(p["name"], p["version"])')

status=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "User-Agent: vouch-protocol-release (+https://vouch-protocol.com)" \
  "https://crates.io/api/v1/crates/${name}/${version}")
if [ "${status}" = "200" ]; then
  echo "${name} ${version} is already on crates.io, skipping"
  exit 0
fi

cargo publish --allow-dirty
echo "${name} ${version} published"
