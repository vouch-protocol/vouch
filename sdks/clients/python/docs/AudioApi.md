# vouch_api_client.AudioApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**audio_detect_audio_detect_post**](AudioApi.md#audio_detect_audio_detect_post) | **POST** /audio/detect | Audio Detect
[**audio_embed_audio_embed_post**](AudioApi.md#audio_embed_audio_embed_post) | **POST** /audio/embed | Audio Embed
[**audio_health_audio_health_get**](AudioApi.md#audio_health_audio_health_get) | **GET** /audio/health | Audio Health
[**audio_sign_audio_sign_post**](AudioApi.md#audio_sign_audio_sign_post) | **POST** /audio/sign | Audio Sign


# **audio_detect_audio_detect_post**
> AudioDetectResponse audio_detect_audio_detect_post(audio_detect_request, authorization=authorization)

Audio Detect

Detect watermark in audio (server-side).

### Example


```python
import vouch_api_client
from vouch_api_client.models.audio_detect_request import AudioDetectRequest
from vouch_api_client.models.audio_detect_response import AudioDetectResponse
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
    api_instance = vouch_api_client.AudioApi(api_client)
    audio_detect_request = vouch_api_client.AudioDetectRequest() # AudioDetectRequest | 
    authorization = 'authorization_example' # str |  (optional)

    try:
        # Audio Detect
        api_response = api_instance.audio_detect_audio_detect_post(audio_detect_request, authorization=authorization)
        print("The response of AudioApi->audio_detect_audio_detect_post:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling AudioApi->audio_detect_audio_detect_post: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **audio_detect_request** | [**AudioDetectRequest**](AudioDetectRequest.md)|  | 
 **authorization** | **str**|  | [optional] 

### Return type

[**AudioDetectResponse**](AudioDetectResponse.md)

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

# **audio_embed_audio_embed_post**
> AudioEmbedResponse audio_embed_audio_embed_post(audio_embed_request, authorization=authorization)

Audio Embed

Embed spread-spectrum watermark into audio (server-side).

### Example


```python
import vouch_api_client
from vouch_api_client.models.audio_embed_request import AudioEmbedRequest
from vouch_api_client.models.audio_embed_response import AudioEmbedResponse
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
    api_instance = vouch_api_client.AudioApi(api_client)
    audio_embed_request = vouch_api_client.AudioEmbedRequest() # AudioEmbedRequest | 
    authorization = 'authorization_example' # str |  (optional)

    try:
        # Audio Embed
        api_response = api_instance.audio_embed_audio_embed_post(audio_embed_request, authorization=authorization)
        print("The response of AudioApi->audio_embed_audio_embed_post:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling AudioApi->audio_embed_audio_embed_post: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **audio_embed_request** | [**AudioEmbedRequest**](AudioEmbedRequest.md)|  | 
 **authorization** | **str**|  | [optional] 

### Return type

[**AudioEmbedResponse**](AudioEmbedResponse.md)

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

# **audio_health_audio_health_get**
> AudioHealthResponse audio_health_audio_health_get()

Audio Health

Audio subsystem health check — no auth required.

### Example


```python
import vouch_api_client
from vouch_api_client.models.audio_health_response import AudioHealthResponse
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
    api_instance = vouch_api_client.AudioApi(api_client)

    try:
        # Audio Health
        api_response = api_instance.audio_health_audio_health_get()
        print("The response of AudioApi->audio_health_audio_health_get:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling AudioApi->audio_health_audio_health_get: %s\n" % e)
```



### Parameters

This endpoint does not need any parameter.

### Return type

[**AudioHealthResponse**](AudioHealthResponse.md)

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

# **audio_sign_audio_sign_post**
> AudioSignResponse audio_sign_audio_sign_post(audio_sign_request, authorization=authorization)

Audio Sign

Full C2PA container signing with VouchCovenant + optional watermark.

### Example


```python
import vouch_api_client
from vouch_api_client.models.audio_sign_request import AudioSignRequest
from vouch_api_client.models.audio_sign_response import AudioSignResponse
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
    api_instance = vouch_api_client.AudioApi(api_client)
    audio_sign_request = vouch_api_client.AudioSignRequest() # AudioSignRequest | 
    authorization = 'authorization_example' # str |  (optional)

    try:
        # Audio Sign
        api_response = api_instance.audio_sign_audio_sign_post(audio_sign_request, authorization=authorization)
        print("The response of AudioApi->audio_sign_audio_sign_post:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling AudioApi->audio_sign_audio_sign_post: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **audio_sign_request** | [**AudioSignRequest**](AudioSignRequest.md)|  | 
 **authorization** | **str**|  | [optional] 

### Return type

[**AudioSignResponse**](AudioSignResponse.md)

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

