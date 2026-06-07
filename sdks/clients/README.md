# Vouch API clients (auto-generated)

Typed HTTP clients for the Vouch API (#35), generated from the OpenAPI spec with
[openapi-generator](https://openapi-generator.tech). These talk to the Vouch
Bridge HTTP service (sign / verify / audio endpoints); they are separate from the
in-process `core` SDKs (which do crypto locally with no network).

```
sdks/clients/
  openapi.json    the source spec (exported from the FastAPI app)
  typescript/     typescript-fetch client
  python/         python client (package: vouch_api_client)
  generate.sh     regenerate both from openapi.json
```

## Endpoints covered

`GET /health`, `POST /sign`, `POST /verify`, and the audio service
(`GET /audio/health`, `POST /audio/embed`, `POST /audio/detect`,
`POST /audio/sign`), with typed request/response models for each.

## Regenerate

```
./generate.sh                 # downloads openapi-generator, regenerates clients
REFRESH_SPEC=1 ./generate.sh  # also re-exports openapi.json from vouch.bridge.server first
```

`generate.sh` downloads `openapi-generator-cli.jar` (gitignored) and runs it with
Java. To regenerate for other languages, add a target, for example:

```
java -jar openapi-generator-cli.jar generate -i openapi.json -g go     -o go
java -jar openapi-generator-cli.jar generate -i openapi.json -g csharp -o csharp
```

## Use

TypeScript:

```ts
import { DefaultApi, Configuration } from './typescript/src';
const api = new DefaultApi(new Configuration({ basePath: 'https://bridge.example' }));
const res = await api.verifyVerifyPost({ verifyRequest: { /* ... */ } });
```

Python:

```python
from vouch_api_client import ApiClient, Configuration
from vouch_api_client.api.default_api import DefaultApi
api = DefaultApi(ApiClient(Configuration(host="https://bridge.example")))
res = api.verify_image_verify_post(verify_request={...})
```
