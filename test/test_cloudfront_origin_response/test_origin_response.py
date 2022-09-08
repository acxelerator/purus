import json

import pytest

from purus.amazon_cloudfront import CloudFrontLambdaEdge
from purus.errors import CloudFrontLambdaEdgeHeaderAppendNoEffectError, CloudFrontLambdaEdgeHeaderEditNotAllowedError


@pytest.fixture
def origin_response_data(path_test_root: str) -> dict:
    path = f"{path_test_root}/test_cloudfront_origin_response/origin_response.example.official.json"
    with open(path, "r") as f:
        data = json.load(f)
    return data


class TestAmazonCloudFront:
    def test_origin_response(self, origin_response_data: dict):

        request = origin_response_data["Records"][0]["cf"]
        lambda_edge = CloudFrontLambdaEdge.from_dict(data=request)
        # response
        assert lambda_edge.response.status == "200"
        assert lambda_edge.response.status_description == "OK"
        # response-headers
        assert lambda_edge.response.get_header(key="X-XSS-Protection").key == "X-XSS-Protection"
        assert lambda_edge.response.get_header(key="x-xss-protection").key == "X-XSS-Protection"
        assert lambda_edge.response.get_header(key="x-xss-protection").value == "1; mode=block"
        assert lambda_edge.response.get_header(key="Content-Length").key == "Content-Length"
        assert lambda_edge.response.get_header(key="content-length").key == "Content-Length"
        assert lambda_edge.response.get_header(key="content-length").value == "9593"
        assert lambda_edge.response.get_header(key="Not-Exist") is None
        # check format() output
        assert request == lambda_edge.format()

    def test_origin_response_header_test(self, origin_response_data: dict):
        request = origin_response_data["Records"][0]["cf"]
        lambda_edge = CloudFrontLambdaEdge.from_dict(data=request)
        # not-allowed headers to append
        with pytest.raises(CloudFrontLambdaEdgeHeaderEditNotAllowedError) as e:
            lambda_edge.append_response_header(key="Transfer-Encoding", value="")
        assert str(e.value) == f"Not allowed to edit Transfer-Encoding at [origin-response]"
        with pytest.raises(CloudFrontLambdaEdgeHeaderEditNotAllowedError) as e:
            lambda_edge.append_response_header(key="Via", value="")
        assert str(e.value) == f"Not allowed to edit Via at [origin-response]"
        # no effect to append headers
        with pytest.raises(CloudFrontLambdaEdgeHeaderAppendNoEffectError) as e:
            lambda_edge.append_request_header(key="any", value="")
        assert str(e.value) == f"No effect to append any at [origin-response]"

        # custom header
        new_lambda_edge = lambda_edge.append_response_header(key="X-Original-Header", value="data")
        assert new_lambda_edge.response.get_header("X-Original-Header").key == "X-Original-Header"
        assert new_lambda_edge.response.get_header("x-original-header").key == "X-Original-Header"
        assert new_lambda_edge.response.get_header("X-Original-Header").value == "data"
