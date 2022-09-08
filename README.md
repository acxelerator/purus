# purus

[![Pytest](https://github.com/acxelerator/purus/actions/workflows/pytest.yml/badge.svg)](https://github.com/acxelerator/purus/actions/workflows/pytest.yml)
[![codecov](https://codecov.io/gh/acxelerator/purus/branch/main/graph/badge.svg?token=2X3BA0RCER)](https://codecov.io/gh/acxelerator/purus)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Imports: isort](https://img.shields.io/badge/%20imports-isort-%231674b1?style=flat&labelColor=ef8336)](https://pycqa.github.io/isort/)
[![Checked with mypy](http://www.mypy-lang.org/static/mypy_badge.svg)](http://mypy-lang.org/)

[![PythonVersion](https://img.shields.io/pypi/pyversions/purus.svg)](https://pypi.org/project/purus/)
[![PiPY](https://img.shields.io/pypi/v/purus.svg)](https://pypi.org/project/purus/)


`purus` parses parameters provided from Lambda@Edge on CloudFront, and it manipulates request and response.
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
    # load data
    lambda_edge = CloudFrontLambdaEdge.from_event(event=event)
    
    # return on error
    if some_error_occurred:
        pseudo_payload = lambda_edge.add_pseudo_response(
            status="400",
            status_description="error_occurred"
        )
        return pseudo_payload.response.format()
    
    # redirect
    if redirect_condition:
        pseudo_payload = lambda_edge.add_pseudo_redirect_response(
            status="307",
            status_description="Redirect",
            location_url="https://redirect.example.com"
        )
        return pseudo_payload.response.format()
    
    # add headers to request
    modified_request = lambda_edge.append_request_header(
        key="X-Original-Header",
        value="Your data"
    ).append_request_header(
        key="X-Original-Header",
        value="Your additional data"
    )
    
    # to request
    return  modified_request.request.format()


```