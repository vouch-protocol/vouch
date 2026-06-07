# AudioDetectRequest

Request body for POST /audio/detect.

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**audio_base64** | **str** | Base64-encoded audio to scan | 

## Example

```python
from vouch_api_client.models.audio_detect_request import AudioDetectRequest

# TODO update the JSON string below
json = "{}"
# create an instance of AudioDetectRequest from a JSON string
audio_detect_request_instance = AudioDetectRequest.from_json(json)
# print the JSON string representation of the object
print(AudioDetectRequest.to_json())

# convert the object into a dict
audio_detect_request_dict = audio_detect_request_instance.to_dict()
# create an instance of AudioDetectRequest from a dict
audio_detect_request_from_dict = AudioDetectRequest.from_dict(audio_detect_request_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


