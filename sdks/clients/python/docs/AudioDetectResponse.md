# AudioDetectResponse

Response body for POST /audio/detect.

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**success** | **bool** |  | 
**detected** | **bool** |  | [optional] [default to False]
**confidence** | **float** |  | [optional] [default to 0.0]
**signer_did** | **str** |  | [optional] 
**payload_hash** | **str** |  | [optional] 
**covenant** | **Dict[str, object]** |  | [optional] 
**error** | **str** |  | [optional] 

## Example

```python
from vouch_api_client.models.audio_detect_response import AudioDetectResponse

# TODO update the JSON string below
json = "{}"
# create an instance of AudioDetectResponse from a JSON string
audio_detect_response_instance = AudioDetectResponse.from_json(json)
# print the JSON string representation of the object
print(AudioDetectResponse.to_json())

# convert the object into a dict
audio_detect_response_dict = audio_detect_response_instance.to_dict()
# create an instance of AudioDetectResponse from a dict
audio_detect_response_from_dict = AudioDetectResponse.from_dict(audio_detect_response_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


