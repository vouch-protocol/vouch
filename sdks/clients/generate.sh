#!/usr/bin/env bash
#
# Regenerate the API clients (#35) from the Vouch Bridge OpenAPI spec.
#
# The spec (openapi.json) is exported from the FastAPI app. Refresh it first if
# the API changed, then regenerate the typed clients with openapi-generator.
#
set -euo pipefail
cd "$(dirname "$0")"

VER="7.7.0"
JAR="openapi-generator-cli.jar"

# Optional: re-export the spec from the running app definition (needs the venv).
if [ "${REFRESH_SPEC:-0}" = "1" ]; then
  ( cd ../.. && python -c "import json; from vouch.bridge.server import app; \
      json.dump(app.openapi(), open('sdks/clients/openapi.json','w'), indent=2)" )
  echo "refreshed openapi.json from vouch.bridge.server"
fi

[ -f "$JAR" ] || curl -sL -o "$JAR" \
  "https://repo1.maven.org/maven2/org/openapitools/openapi-generator-cli/$VER/openapi-generator-cli-$VER.jar"

echo "==> TypeScript (typescript-fetch)"
java -jar "$JAR" generate -i openapi.json -g typescript-fetch -o typescript \
  --additional-properties=npmName=@vouch-protocol-official/api-client,supportsES6=true \
  --skip-validate-spec

echo "==> Python"
java -jar "$JAR" generate -i openapi.json -g python -o python \
  --additional-properties=packageName=vouch_api_client,projectName=vouch-api-client \
  --skip-validate-spec

echo "==> done: typescript/ and python/ regenerated"
