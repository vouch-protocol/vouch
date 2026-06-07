# AudioSignResponse

Response body for POST /audio/sign.

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**success** | **bool** |  | 
**signed_audio_base64** | **str** |  | [optional] 
**manifest_hash** | **str** |  | [optional] 
**watermark_embedded** | **bool** |  | [optional] [default to False]
**timestamp** | **str** |  | [optional] 
**error** | **str** |  | [optional] 

## Example

```python
from vouch_api_client.models.audio_sign_response import AudioSignResponse

# TODO update the JSON string below
json = "{}"
# create an instance of AudioSignResponse from a JSON string
audio_sign_response_instance = AudioSignResponse.from_json(json)
# print the JSON string representation of the object
print(AudioSignResponse.to_json())

# convert the object into a dict
audio_sign_response_dict = audio_sign_response_instance.to_dict()
# create an instance of AudioSignResponse from a dict
audio_sign_response_from_dict = AudioSignResponse.from_dict(audio_sign_response_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


