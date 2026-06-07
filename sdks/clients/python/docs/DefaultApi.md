# vouch_api_client.DefaultApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**health_health_get**](DefaultApi.md#health_health_get) | **GET** /health | Health
[**sign_image_sign_post**](DefaultApi.md#sign_image_sign_post) | **POST** /sign | Sign Image
[**verify_image_verify_post**](DefaultApi.md#verify_image_verify_post) | **POST** /verify | Verify Image


# **health_health_get**
> HealthResponse health_health_get()

Health

Health check — no auth required.

### Example


```python
import vouch_api_client
from vouch_api_client.models.health_response import HealthResponse
from vouch_api_client.rest import ApiException
from pprint import pprint

# Defining the host is optional and defaults to http://localhost
# See configuration.py for a list of all supported configuration parameters.
configuration = vouch_api_client.Configuration(
    host = "http://localhost"
)


# Enter a context with an instance of the API client
with vouch_api_client.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = vouch_api_client.DefaultApi(api_client)

    try:
        # Health
        api_response = api_instance.health_health_get()
        print("The response of DefaultApi->health_health_get:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling DefaultApi->health_health_get: %s\n" % e)
```



### Parameters

This endpoint does not need any parameter.

### Return type

[**HealthResponse**](HealthResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Successful Response |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **sign_image_sign_post**
> SignResponse sign_image_sign_post(sign_request, authorization=authorization)

Sign Image

Sign an image with C2PA manifest and QR badge.

### Example


```python
import vouch_api_client
from vouch_api_client.models.sign_request import SignRequest
from vouch_api_client.models.sign_response import SignResponse
from vouch_api_client.rest import ApiException
from pprint import pprint

# Defining the host is optional and defaults to http://localhost
# See configuration.py for a list of all supported configuration parameters.
configuration = vouch_api_client.Configuration(
    host = "http://localhost"
)


# Enter a context with an instance of the API client
with vouch_api_client.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = vouch_api_client.DefaultApi(api_client)
    sign_request = vouch_api_client.SignRequest() # SignRequest | 
    authorization = 'authorization_example' # str |  (optional)

    try:
        # Sign Image
        api_response = api_instance.sign_image_sign_post(sign_request, authorization=authorization)
        print("The response of DefaultApi->sign_image_sign_post:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling DefaultApi->sign_image_sign_post: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **sign_request** | [**SignRequest**](SignRequest.md)|  | 
 **authorization** | **str**|  | [optional] 

### Return type

[**SignResponse**](SignResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Successful Response |  -  |
**422** | Validation Error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **verify_image_verify_post**
> VerifyResponse verify_image_verify_post(verify_request, authorization=authorization)

Verify Image

Verify a signed image's C2PA manifest.

### Example


```python
import vouch_api_client
from vouch_api_client.models.verify_request import VerifyRequest
from vouch_api_client.models.verify_response import VerifyResponse
from vouch_api_client.rest import ApiException
from pprint import pprint

# Defining the host is optional and defaults to http://localhost
# See configuration.py for a list of all supported configuration parameters.
configuration = vouch_api_client.Configuration(
    host = "http://localhost"
)


# Enter a context with an instance of the API client
with vouch_api_client.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = vouch_api_client.DefaultApi(api_client)
    verify_request = vouch_api_client.VerifyRequest() # VerifyRequest | 
    authorization = 'authorization_example' # str |  (optional)

    try:
        # Verify Image
        api_response = api_instance.verify_image_verify_post(verify_request, authorization=authorization)
        print("The response of DefaultApi->verify_image_verify_post:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling DefaultApi->verify_image_verify_post: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **verify_request** | [**VerifyRequest**](VerifyRequest.md)|  | 
 **authorization** | **str**|  | [optional] 

### Return type

[**VerifyResponse**](VerifyResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Successful Response |  -  |
**422** | Validation Error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

