# AudioEmbedResponse

Response body for POST /audio/embed.

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**success** | **bool** |  | 
**audio_base64** | **str** |  | [optional] 
**watermark_id** | **str** |  | [optional] 
**audio_hash** | **str** |  | [optional] 
**payload_hash** | **str** |  | [optional] 
**timestamp** | **str** |  | [optional] 
**error** | **str** |  | [optional] 

## Example

```python
from vouch_api_client.models.audio_embed_response import AudioEmbedResponse

# TODO update the JSON string below
json = "{}"
# create an instance of AudioEmbedResponse from a JSON string
audio_embed_response_instance = AudioEmbedResponse.from_json(json)
# print the JSON string representation of the object
print(AudioEmbedResponse.to_json())

# convert the object into a dict
audio_embed_response_dict = audio_embed_response_instance.to_dict()
# create an instance of AudioEmbedResponse from a dict
audio_embed_response_from_dict = AudioEmbedResponse.from_dict(audio_embed_response_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


