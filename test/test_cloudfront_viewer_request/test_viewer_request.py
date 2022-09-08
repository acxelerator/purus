import json
from datetime import datetime, timezone

import pytest

from purus.amazon_cloudfront import CloudFrontLambdaEdge
from purus.errors import (
    CloudFrontLambdaEdgeError,
    CloudFrontLambdaEdgeHeaderEditNotAllowedError,
    CloudFrontLambdaEdgeObjectNotFoundError,
)


@pytest.fixture
def viewer_request_data(path_test_root: str) -> dict:
    path = f"{path_test_root}/test_cloudfront_viewer_request/viewer_request.example.official.json"
    with open(path, "r") as f:
        data = json.load(f)
    return data


@pytest.fixture
def viewer_request_data_cookie(path_test_root: str) -> dict:
    path = f"{path_test_root}/test_cloudfront_viewer_request/viewer_request.example.cookie-ver.json"
    with open(path, "r") as f:
        data = json.load(f)
    return data


class TestCloudFrontViewerRequest:
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

        # from_event()
        _ = CloudFrontLambdaEdge.from_event(event=viewer_request_data)

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
            key="example_key", value="example_value", expires=datetime.fromtimestamp(0, tz=timezone.utc)
        )
        assert set_expires_cookie_lambda_edge_2.response.get_header("Set-Cookie").key == "Set-Cookie"
        assert set_expires_cookie_lambda_edge_2.response.get_header("set-cookie").key == "Set-Cookie"
        assert (
            set_expires_cookie_lambda_edge_2.response.get_header("set-cookie").value
            == "example_key=example_value; Expires=Thu, 01 Jan 1970 00:00:00 GMT; SameSite=Lax; Secure; HttpOnly"
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

    def test_viewer_request_get_cookies_none_test(self, viewer_request_data: dict):
        request = viewer_request_data["Records"][0]["cf"]
        lambda_edge = CloudFrontLambdaEdge.from_dict(data=request)

        cookies = lambda_edge.request.get_cookies()
        assert cookies is None

    def test_viewer_request_get_cookies_test(self, viewer_request_data_cookie: dict):
        request = viewer_request_data_cookie["Records"][0]["cf"]
        lambda_edge = CloudFrontLambdaEdge.from_dict(data=request)

        cookies = lambda_edge.request.get_cookies()
        cookie_1 = [v for v in cookies if v.key == "example-key-1"][0]
        assert cookie_1.key == "example-key-1"
        assert cookie_1.value == "value1"
        cookie_2 = [v for v in cookies if v.key == "example-key-2"][0]
        assert cookie_2.key == "example-key-2"
        assert cookie_2.value == "value2"

    def test_error(self):
        with pytest.raises(CloudFrontLambdaEdgeError):
            CloudFrontLambdaEdge.from_event(event={})
        with pytest.raises(CloudFrontLambdaEdgeError):
            CloudFrontLambdaEdge.from_event(event={"Records": []})
        with pytest.raises(CloudFrontLambdaEdgeError):
            CloudFrontLambdaEdge.from_event(event={"Records": ["v1", "v2"]})
        with pytest.raises(CloudFrontLambdaEdgeError):
            CloudFrontLambdaEdge.from_event(event={"Records": [{"not_cf": "v1"}]})
