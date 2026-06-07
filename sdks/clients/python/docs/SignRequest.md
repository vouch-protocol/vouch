# SignRequest

Request body for POST /sign.

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**image_base64** | **str** | Base64-encoded source image | 
**did** | **str** | DID of the signer | 
**display_name** | **str** | Human-readable signer name | 
**email** | **str** |  | [optional] 
**credential_type** | **str** | FREE or PRO | [optional] [default to 'FREE']
**title** | **str** |  | [optional] 
**badge_position** | **str** |  | [optional] 
**shortlink_domain** | **str** |  | [optional] 

## Example

```python
from vouch_api_client.models.sign_request import SignRequest

# TODO update the JSON string below
json = "{}"
# create an instance of SignRequest from a JSON string
sign_request_instance = SignRequest.from_json(json)
# print the JSON string representation of the object
print(SignRequest.to_json())

# convert the object into a dict
sign_request_dict = sign_request_instance.to_dict()
# create an instance of SignRequest from a dict
sign_request_from_dict = SignRequest.from_dict(sign_request_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


