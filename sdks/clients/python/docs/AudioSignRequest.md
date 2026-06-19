# AudioSignRequest

Request body for POST /audio/sign — full C2PA container signing.

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**audio_base64** | **str** | Base64-encoded audio file | 
**did** | **str** | DID of the signer | 
**display_name** | **str** | Human-readable signer name | [optional] [default to '']
**covenant** | **Dict[str, object]** |  | [optional] 
**title** | **str** |  | [optional] 

## Example

```python
from vouch_api_client.models.audio_sign_request import AudioSignRequest

# TODO update the JSON string below
json = "{}"
# create an instance of AudioSignRequest from a JSON string
audio_sign_request_instance = AudioSignRequest.from_json(json)
# print the JSON string representation of the object
print(AudioSignRequest.to_json())

# convert the object into a dict
audio_sign_request_dict = audio_sign_request_instance.to_dict()
# create an instance of AudioSignRequest from a dict
audio_sign_request_from_dict = AudioSignRequest.from_dict(audio_sign_request_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


