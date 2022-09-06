from datetime import datetime
import json

import pytest

from purus.amazon_cloudfront import CloudFrontLambdaEdge
from purus.errors import (
    CloudFrontLambdaEdgeError,
    CloudFrontLambdaEdgeHeaderAppendNoEffectError,
    CloudFrontLambdaEdgeHeaderEditNotAllowedError,
    CloudFrontLambdaEdgeObjectNotFoundError,
)


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


@pytest.fixture
def origin_response_data(path_amazon_cloudfront: str) -> dict:
    with open(f"{path_amazon_cloudfront}/origin_response.example.official.json", "r") as f:
        data = json.load(f)
    return data


@pytest.fixture
def viewer_response_data(path_amazon_cloudfront: str) -> dict:
    with open(f"{path_amazon_cloudfront}/viewer_response.example.official.json", "r") as f:
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

        # not-allowed headers to append
        with pytest.raises(CloudFrontLambdaEdgeHeaderEditNotAllowedError) as e:
            lambda_edge.append_request_header(key="Content-Length", value="")
        assert str(e.value) == f"Not allowed to edit Content-Length at [viewer-request]"
        with pytest.raises(CloudFrontLambdaEdgeHeaderEditNotAllowedError) as e:
            lambda_edge.append_request_header(key="Host", value="")
        assert str(e.value) == f"Not allowed to edit Host at [viewer-request]"
        with pytest.raises(CloudFrontLambdaEdgeHeaderEditNotAllowedError) as e:
            lambda_edge.append_request_header(key="Transfer-Encoding", value="")
        assert str(e.value) == f"Not allowed to edit Transfer-Encoding at [viewer-request]"
        with pytest.raises(CloudFrontLambdaEdgeHeaderEditNotAllowedError) as e:
            lambda_edge.append_request_header(key="Via", value="")
        assert str(e.value) == f"Not allowed to edit Via at [viewer-request]"

        # no effect to append headers
        with pytest.raises(CloudFrontLambdaEdgeObjectNotFoundError) as e:
            lambda_edge.append_response_header(key="any", value="")
        assert str(e.value) == f"Not found [response]"

        new_lambda_edge = lambda_edge.append_request_header(key="X-Original-Header", value="data")
        assert new_lambda_edge.request.get_header("X-Original-Header").key == "X-Original-Header"
        assert new_lambda_edge.request.get_header("x-original-header").key == "X-Original-Header"
        assert new_lambda_edge.request.get_header("X-Original-Header").value == "data"

    def test_viewer_request_pseudo_response_test(self, viewer_request_data: dict):
        request = viewer_request_data["Records"][0]["cf"]
        lambda_edge = CloudFrontLambdaEdge.from_dict(data=request)

        # redirect_response
        redirect_lambda_edge = lambda_edge.add_pseudo_redirect_response(
            status="307", status_description="Redirect", location_url="https://example.com"
        )
        assert redirect_lambda_edge.response.get_header("location").key == "location"
        assert redirect_lambda_edge.response.get_header("location").value == "https://example.com"
        assert redirect_lambda_edge.response.status == "307"
        assert redirect_lambda_edge.response.status_description == "Redirect"

    def test_viewer_request_set_cookie_test(self, viewer_request_data: dict):
        request = viewer_request_data["Records"][0]["cf"]
        lambda_edge = CloudFrontLambdaEdge.from_dict(data=request)

        # no effect to append headers
        with pytest.raises(CloudFrontLambdaEdgeObjectNotFoundError) as e:
            lambda_edge.append_response_set_cookie_header(key="example_key", value="example_value")
        assert str(e.value) == f"Not found [response]"

        # default-cookie
        pseudo_lambda_edge = lambda_edge.add_pseudo_response(status="200", status_description="OK!")
        set_default_cookie_lambda_edge = pseudo_lambda_edge.append_response_set_cookie_header(
            key="example_key", value="example_value"
        )
        assert set_default_cookie_lambda_edge.response.get_header("Set-Cookie").key == "Set-Cookie"
        assert set_default_cookie_lambda_edge.response.get_header("set-cookie").key == "Set-Cookie"
        assert (
            set_default_cookie_lambda_edge.response.get_header("set-cookie").value
            == "example_key=example_value; SameSite=Lax; Secure; HttpOnly"
        )

        # expires-cookie
        pseudo_lambda_edge = lambda_edge.add_pseudo_response(status="200", status_description="OK!")
        with pytest.raises(CloudFrontLambdaEdgeError):
            pseudo_lambda_edge.append_response_set_cookie_header(
                key="example_key", value="example_value", expires="invalid-time-format"
            )
        set_expires_cookie_lambda_edge = pseudo_lambda_edge.append_response_set_cookie_header(
            key="example_key", value="example_value", expires="Thu, 01 Jan 1970 00:00:00 GMT"
        )
        assert set_expires_cookie_lambda_edge.response.get_header("Set-Cookie").key == "Set-Cookie"
        assert set_expires_cookie_lambda_edge.response.get_header("set-cookie").key == "Set-Cookie"
        assert (
            set_expires_cookie_lambda_edge.response.get_header("set-cookie").value
            == "example_key=example_value; Expires=Thu, 01 Jan 1970 00:00:00 GMT; SameSite=Lax; Secure; HttpOnly"
        )
        pseudo_lambda_edge = lambda_edge.add_pseudo_response(status="200", status_description="OK!")
        set_expires_cookie_lambda_edge_2 = pseudo_lambda_edge.append_response_set_cookie_header(
            key="example_key", value="example_value", expires=datetime.fromtimestamp(0)
        )
        assert set_expires_cookie_lambda_edge_2.response.get_header("Set-Cookie").key == "Set-Cookie"
        assert set_expires_cookie_lambda_edge_2.response.get_header("set-cookie").key == "Set-Cookie"
        assert (
            set_expires_cookie_lambda_edge_2.response.get_header("set-cookie").value
            == "example_key=example_value; Expires=Thu, 01 Jan 1970 09:00:00 GMT; SameSite=Lax; Secure; HttpOnly"
        )

        # domain-cookie
        pseudo_lambda_edge = lambda_edge.add_pseudo_response(status="200", status_description="OK!")
        set_domain_cookie_lambda_edge = pseudo_lambda_edge.append_response_set_cookie_header(
            key="example_key", value="example_value", domain="example.com"
        )
        assert set_domain_cookie_lambda_edge.response.get_header("Set-Cookie").key == "Set-Cookie"
        assert set_domain_cookie_lambda_edge.response.get_header("set-cookie").key == "Set-Cookie"
        assert (
            set_domain_cookie_lambda_edge.response.get_header("set-cookie").value
            == "example_key=example_value; Domain=example.com; SameSite=Lax; Secure; HttpOnly"
        )

        # path-cookie
        pseudo_lambda_edge = lambda_edge.add_pseudo_response(status="200", status_description="OK!")
        set_domain_cookie_lambda_edge = pseudo_lambda_edge.append_response_set_cookie_header(
            key="example_key", value="example_value", path="/example"
        )
        assert set_domain_cookie_lambda_edge.response.get_header("Set-Cookie").key == "Set-Cookie"
        assert set_domain_cookie_lambda_edge.response.get_header("set-cookie").key == "Set-Cookie"
        assert (
            set_domain_cookie_lambda_edge.response.get_header("set-cookie").value
            == "example_key=example_value; Path=/example; SameSite=Lax; Secure; HttpOnly"
        )

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

        # not-allowed headers to append
        with pytest.raises(CloudFrontLambdaEdgeHeaderEditNotAllowedError) as e:
            lambda_edge.append_request_header(key="Accept-Encoding", value="")
        assert str(e.value) == f"Not allowed to edit Accept-Encoding at [origin-request]"
        with pytest.raises(CloudFrontLambdaEdgeHeaderEditNotAllowedError) as e:
            lambda_edge.append_request_header(key="Content-Length", value="")
        assert str(e.value) == f"Not allowed to edit Content-Length at [origin-request]"
        with pytest.raises(CloudFrontLambdaEdgeHeaderEditNotAllowedError) as e:
            lambda_edge.append_request_header(key="If-Modified-Since", value="")
        assert str(e.value) == f"Not allowed to edit If-Modified-Since at [origin-request]"
        with pytest.raises(CloudFrontLambdaEdgeHeaderEditNotAllowedError) as e:
            lambda_edge.append_request_header(key="If-None-Match", value="")
        assert str(e.value) == f"Not allowed to edit If-None-Match at [origin-request]"
        with pytest.raises(CloudFrontLambdaEdgeHeaderEditNotAllowedError) as e:
            lambda_edge.append_request_header(key="If-Range", value="")
        assert str(e.value) == f"Not allowed to edit If-Range at [origin-request]"
        with pytest.raises(CloudFrontLambdaEdgeHeaderEditNotAllowedError) as e:
            lambda_edge.append_request_header(key="If-Unmodified-Since", value="")
        assert str(e.value) == f"Not allowed to edit If-Unmodified-Since at [origin-request]"
        with pytest.raises(CloudFrontLambdaEdgeHeaderEditNotAllowedError) as e:
            lambda_edge.append_request_header(key="Transfer-Encoding", value="")
        assert str(e.value) == f"Not allowed to edit Transfer-Encoding at [origin-request]"
        with pytest.raises(CloudFrontLambdaEdgeHeaderEditNotAllowedError) as e:
            lambda_edge.append_request_header(key="Via", value="")
        assert str(e.value) == f"Not allowed to edit Via at [origin-request]"
        # no effect to append headers
        with pytest.raises(CloudFrontLambdaEdgeObjectNotFoundError) as e:
            lambda_edge.append_response_header(key="any", value="")
        assert str(e.value) == f"Not found [response]"

        # headers to append
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
