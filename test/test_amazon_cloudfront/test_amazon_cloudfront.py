import json

import pytest

from purus.amazon_cloudfront import CloudFrontLambdaEdge, CloudFrontLambdaEdgeError


@pytest.fixture
def path_amazon_cloudfront(path_test_root: str):
    yield f"{path_test_root}/test_amazon_cloudfront"


@pytest.fixture
def viewer_request_data(path_amazon_cloudfront: str) -> dict:
    with open(f"{path_amazon_cloudfront}/viewer_request.example.official.json", "r") as f:
        data = json.load(f)
    return data


@pytest.fixture
def origin_request_data(path_amazon_cloudfront: str) -> dict:
    with open(f"{path_amazon_cloudfront}/origin_request.example.official.json", "r") as f:
        data = json.load(f)
    return data


class TestAmazonCloudFront:
    def test_viewer_request(self, viewer_request_data: dict):
        request = viewer_request_data["Records"][0]["cf"]
        lambda_edge = CloudFrontLambdaEdge.from_dict(data=request)

        # check config
        assert lambda_edge.config.distribution_domain_name == "d111111abcdef8.cloudfront.net"
        assert lambda_edge.config.distribution_id == "EDFDVBD6EXAMPLE"
        assert lambda_edge.config.event_type == "viewer-request"
        assert lambda_edge.config.request_id == "4TyzHTaYWb1GX1qTfsHhEqV6HUDd_BzoBZnwfnvQc_1oF26ClkoUSEQ=="
        # check request
        assert lambda_edge.request.method == "GET"
        assert lambda_edge.request.querystring == ""
        assert lambda_edge.request.uri == "/"
        assert lambda_edge.request.client_ip == "203.0.113.178"
        assert len(lambda_edge.request.headers) == 3
        assert lambda_edge.request.get_header(key="Host").key == "Host"
        assert lambda_edge.request.get_header(key="host").key == "Host"
        assert lambda_edge.request.get_header(key="host").value == "d111111abcdef8.cloudfront.net"
        assert lambda_edge.request.get_header(key="User-Agent").key == "User-Agent"
        assert lambda_edge.request.get_header(key="user-agent").key == "User-Agent"
        assert lambda_edge.request.get_header(key="user-agent").value == "curl/7.66.0"
        assert lambda_edge.request.get_header(key="accept").key == "accept"
        assert lambda_edge.request.get_header(key="accept").value == "*/*"
        assert lambda_edge.request.get_header(key="Not-Exist") is None
        # check format() output
        assert request == lambda_edge.format()

    def test_viewer_request_header_test(self, viewer_request_data: dict):
        request = viewer_request_data["Records"][0]["cf"]
        lambda_edge = CloudFrontLambdaEdge.from_dict(data=request)

        with pytest.raises(CloudFrontLambdaEdgeError):
            lambda_edge.append_request_header(key="Content-Length", value="")
        with pytest.raises(CloudFrontLambdaEdgeError):
            lambda_edge.append_request_header(key="Host", value="")
        with pytest.raises(CloudFrontLambdaEdgeError):
            lambda_edge.append_request_header(key="Transfer-Encoding", value="")
        with pytest.raises(CloudFrontLambdaEdgeError):
            lambda_edge.append_request_header(key="Via", value="")

        new_lambda_edge = lambda_edge.append_request_header(key="X-Original-Header", value="data")
        assert new_lambda_edge.request.get_header("X-Original-Header").key == "X-Original-Header"
        assert new_lambda_edge.request.get_header("x-original-header").key == "X-Original-Header"
        assert new_lambda_edge.request.get_header("X-Original-Header").value == "data"

    def test_origin_request(self, origin_request_data: dict):

        request = origin_request_data["Records"][0]["cf"]
        lambda_edge = CloudFrontLambdaEdge.from_dict(data=request)

        # check config
        assert lambda_edge.config.distribution_domain_name == "d111111abcdef8.cloudfront.net"
        assert lambda_edge.config.distribution_id == "EDFDVBD6EXAMPLE"
        assert lambda_edge.config.event_type == "origin-request"
        assert lambda_edge.config.request_id == "4TyzHTaYWb1GX1qTfsHhEqV6HUDd_BzoBZnwfnvQc_1oF26ClkoUSEQ=="
        # check request
        assert lambda_edge.request.method == "GET"
        assert lambda_edge.request.querystring == ""
        assert lambda_edge.request.uri == "/"
        assert lambda_edge.request.client_ip == "203.0.113.178"
        assert len(lambda_edge.request.headers) == 5
        assert lambda_edge.request.get_header(key="X-Forwarded-For").key == "X-Forwarded-For"
        assert lambda_edge.request.get_header(key="x-forwarded-for").key == "X-Forwarded-For"
        assert lambda_edge.request.get_header(key="x-forwarded-for").value == "203.0.113.178"
        assert lambda_edge.request.get_header(key="User-Agent").key == "User-Agent"
        assert lambda_edge.request.get_header(key="user-agent").key == "User-Agent"
        assert lambda_edge.request.get_header(key="user-agent").value == "Amazon CloudFront"
        assert lambda_edge.request.get_header(key="Via").key == "Via"
        assert lambda_edge.request.get_header(key="via").key == "Via"
        assert (
            lambda_edge.request.get_header(key="via").value
            == "2.0 2afae0d44e2540f472c0635ab62c232b.cloudfront.net (CloudFront)"
        )
        assert lambda_edge.request.get_header(key="Host").key == "Host"
        assert lambda_edge.request.get_header(key="host").key == "Host"
        assert lambda_edge.request.get_header(key="host").value == "example.org"
        assert lambda_edge.request.get_header(key="Cache-Control").key == "Cache-Control"
        assert lambda_edge.request.get_header(key="cache-control").key == "Cache-Control"
        assert lambda_edge.request.get_header(key="cache-control").value == "no-cache, cf-no-cache"
        # check request.origin
        assert lambda_edge.request.origin.path == ""
        assert lambda_edge.request.origin.keepalive_timeout == 5
        assert lambda_edge.request.origin.port == 443
        assert lambda_edge.request.origin.protocol == "https"
        assert lambda_edge.request.origin.read_timeout == 30
        assert lambda_edge.request.origin.ssl_protocols == ["TLSv1", "TLSv1.1", "TLSv1.2"]
        assert lambda_edge.request.origin.custom_headers == []
        assert lambda_edge.request.origin.domain_name == "example.org"
        # check format() output
        assert request == lambda_edge.format()

    def test_origin_request_header_test(self, origin_request_data: dict):
        request = origin_request_data["Records"][0]["cf"]
        lambda_edge = CloudFrontLambdaEdge.from_dict(data=request)

        with pytest.raises(CloudFrontLambdaEdgeError):
            lambda_edge.append_request_header(key="Accept-Encoding", value="")
        with pytest.raises(CloudFrontLambdaEdgeError):
            lambda_edge.append_request_header(key="Content-Length", value="")
        with pytest.raises(CloudFrontLambdaEdgeError):
            lambda_edge.append_request_header(key="If-Modified-Since", value="")
        with pytest.raises(CloudFrontLambdaEdgeError):
            lambda_edge.append_request_header(key="If-None-Match", value="")
        with pytest.raises(CloudFrontLambdaEdgeError):
            lambda_edge.append_request_header(key="If-Range", value="")
        with pytest.raises(CloudFrontLambdaEdgeError):
            lambda_edge.append_request_header(key="If-Unmodified-Since", value="")
        with pytest.raises(CloudFrontLambdaEdgeError):
            lambda_edge.append_request_header(key="Transfer-Encoding", value="")
        with pytest.raises(CloudFrontLambdaEdgeError):
            lambda_edge.append_request_header(key="Via", value="")

        new_lambda_edge = lambda_edge.append_request_header(key="X-Original-Header", value="data")
        assert new_lambda_edge.request.get_header("X-Original-Header").key == "X-Original-Header"
        assert new_lambda_edge.request.get_header("x-original-header").key == "X-Original-Header"
        assert new_lambda_edge.request.get_header("X-Original-Header").value == "data"

    def test_origin_request_params_test(self, origin_request_data: dict):
        request = origin_request_data["Records"][0]["cf"]
        lambda_edge = CloudFrontLambdaEdge.from_dict(data=request)
        assert lambda_edge.request.querystring == ""
        assert lambda_edge.request.uri == "/"

        # querystring
        new_lambda_edge = lambda_edge.update_request_querystring(querystring="data")
        assert new_lambda_edge.request.querystring == "data"
        # uri
        new_lambda_edge = lambda_edge.update_request_uri("/new_path")
        assert new_lambda_edge.request.uri == "/new_path"
        with pytest.raises(CloudFrontLambdaEdgeError):
            lambda_edge.update_request_uri("new_path")
