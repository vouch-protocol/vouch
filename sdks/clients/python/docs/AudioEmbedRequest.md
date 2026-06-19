# AudioEmbedRequest

Request body for POST /audio/embed.

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**audio_base64** | **str** | Base64-encoded audio (WAV/MP3/FLAC/OGG/M4A/AAC/Opus/WebM) | 
**did** | **str** | DID of the signer | 
**display_name** | **str** | Human-readable signer name | [optional] [default to '']
**covenant** | **Dict[str, object]** |  | [optional] 

## Example

```python
from vouch_api_client.models.audio_embed_request import AudioEmbedRequest

# TODO update the JSON string below
json = "{}"
# create an instance of AudioEmbedRequest from a JSON string
audio_embed_request_instance = AudioEmbedRequest.from_json(json)
# print the JSON string representation of the object
print(AudioEmbedRequest.to_json())

# convert the object into a dict
audio_embed_request_dict = audio_embed_request_instance.to_dict()
# create an instance of AudioEmbedRequest from a dict
audio_embed_request_from_dict = AudioEmbedRequest.from_dict(audio_embed_request_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


