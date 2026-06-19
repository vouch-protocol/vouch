# AudioHealthResponse

Response body for GET /audio/health.

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**status** | **str** |  | 
**version** | **str** |  | 
**numpy_available** | **bool** |  | 
**c2pa_available** | **bool** |  | 
**audioseal_available** | **bool** |  | 
**watermarker** | **str** |  | 

## Example

```python
from vouch_api_client.models.audio_health_response import AudioHealthResponse

# TODO update the JSON string below
json = "{}"
# create an instance of AudioHealthResponse from a JSON string
audio_health_response_instance = AudioHealthResponse.from_json(json)
# print the JSON string representation of the object
print(AudioHealthResponse.to_json())

# convert the object into a dict
audio_health_response_dict = audio_health_response_instance.to_dict()
# create an instance of AudioHealthResponse from a dict
audio_health_response_from_dict = AudioHealthResponse.from_dict(audio_health_response_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


