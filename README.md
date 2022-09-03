# purus

`purus` parses parameters provided from AWS services.
It is named after The Purus River, or a tributary of The Amazon River.


## Install

```shell
$ pip install purus
```

## Usage

### CloudFront:Lambda@Edge

`purus` can parse parameters of

- viewer-request
- origin-request
- origin-response
- viewer-response

```python
# Lambda@Edge
from purus.amazon_cloudfront import CloudFrontLambdaEdge

# on viewer-request or origin-request
def lambda_handler(event: dict, _):
    data = event["Records"][0]["cf"]
    # load data
    lambda_edge = CloudFrontLambdaEdge.from_dict(data=data)
    
    # return on error
    if some_error_occurred:
        response = lambda_edge.add_pseudo_response(
            status="400",
            status_description="error_occurred"
        )
        return response
    
    # add headers to request
    modified_request = lambda_edge.append_request_header(
        key="X-Original-Header",
        value="Your data"
    ).append_request_header(
        key="X-Original-Header",
        value="Your additional data"
    )
    
    # to request
    return  modified_request.request


```