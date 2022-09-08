import json

import pytest

from purus.amazon_cloudfront import CloudFrontLambdaEdge
from purus.errors import CloudFrontLambdaEdgeHeaderAppendNoEffectError, CloudFrontLambdaEdgeHeaderEditNotAllowedError


@pytest.fixture
def viewer_response_data(path_test_root: str) -> dict:
    path = f"{path_test_root}/test_cloudfront_viewer_response/viewer_response.example.official.json"
    with open(path, "r") as f:
        data = json.load(f)
    return data


class TestAmazonCloudFront:
    def test_viewer_response(self, viewer_response_data: dict):

        request = viewer_response_data["Records"][0]["cf"]
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

    def test_viewer_response_header_test(self, viewer_response_data: dict):
        request = viewer_response_data["Records"][0]["cf"]
        lambda_edge = CloudFrontLambdaEdge.from_dict(data=request)
        # not-allowed headers to append
        with pytest.raises(CloudFrontLambdaEdgeHeaderEditNotAllowedError) as e:
            lambda_edge.append_response_header(key="Content-Length", value="")
        assert str(e.value) == f"Not allowed to edit Content-Length at [viewer-response]"
        with pytest.raises(CloudFrontLambdaEdgeHeaderEditNotAllowedError) as e:
            lambda_edge.append_response_header(key="Content-Encoding", value="")
        assert str(e.value) == f"Not allowed to edit Content-Encoding at [viewer-response]"
        with pytest.raises(CloudFrontLambdaEdgeHeaderEditNotAllowedError) as e:
            lambda_edge.append_response_header(key="Transfer-Encoding", value="")
        assert str(e.value) == f"Not allowed to edit Transfer-Encoding at [viewer-response]"
        with pytest.raises(CloudFrontLambdaEdgeHeaderEditNotAllowedError) as e:
            lambda_edge.append_response_header(key="Warning", value="")
        assert str(e.value) == f"Not allowed to edit Warning at [viewer-response]"
        with pytest.raises(CloudFrontLambdaEdgeHeaderEditNotAllowedError) as e:
            lambda_edge.append_response_header(key="Via", value="")
        assert str(e.value) == f"Not allowed to edit Via at [viewer-response]"
        # no effect to append headers
        with pytest.raises(CloudFrontLambdaEdgeHeaderAppendNoEffectError) as e:
            lambda_edge.append_request_header(key="any", value="")
        assert str(e.value) == f"No effect to append any at [viewer-response]"

        # custom header
        new_lambda_edge = lambda_edge.append_response_header(key="X-Original-Header", value="data")
        assert new_lambda_edge.response.get_header("X-Original-Header").key == "X-Original-Header"
        assert new_lambda_edge.response.get_header("x-original-header").key == "X-Original-Header"
        assert new_lambda_edge.response.get_header("X-Original-Header").value == "data"
