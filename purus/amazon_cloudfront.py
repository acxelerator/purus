from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from .errors import (
    CloudFrontLambdaEdgeError,
    CloudFrontLambdaEdgeHeaderAppendNoEffectError,
    CloudFrontLambdaEdgeHeaderEditNotAllowedError,
    CloudFrontLambdaEdgeObjectNotFoundError,
)

__all__ = ["CloudFrontLambdaEdge"]


@dataclass(frozen=True)
class CloudFrontLambdaEdgeConfig:
    distribution_domain_name: str = field(metadata={"readonly": True})
    distribution_id: str = field(metadata={"readonly": True})
    event_type: str = field(metadata={"readonly": True})
    request_id: str = field(metadata={"readonly": True})

    @staticmethod
    def from_dict(data: dict):
        return CloudFrontLambdaEdgeConfig(
            distribution_domain_name=data["distributionDomainName"],
            distribution_id=data["distributionId"],
            event_type=data["eventType"],
            request_id=data["requestId"],
        )

    def format(self) -> dict:
        return {
            "distributionDomainName": self.distribution_domain_name,
            "distributionId": self.distribution_id,
            "eventType": self.event_type,
            "requestId": self.request_id,
        }


@dataclass(frozen=True)
class CloudFrontLambdaEdgeHeader:
    key: str = field(metadata={"readonly": False})
    value: str = field(metadata={"readonly": False})

    @staticmethod
    def check_allowed_custom_header_key(header_key: str) -> bool:
        """

        Returns: allowed: True

        """
        header_key_ = header_key.lower()
        if header_key_.startswith("x-amz-") or header_key_.startswith("x-edge-"):
            return False
        not_allowed_header_keys = [
            "Cache-Control",
            "Connection",
            "Content-Length",
            "Cookie",
            "Host",
            "If-Match",
            "If-Modified-Since",
            "If-None-Match",
            "If-Range",
            "If-Unmodified-Since",
            "Max-Forwards",
            "Pragma",
            "Proxy-Authorization",
            "Proxy-Connection",
            "Range",
            "Request-Range",
            "TE",
            "Trailer",
            "Transfer-Encoding",
            "Upgrade",
            "Via",
            "X-Real-Ip",
        ]
        not_allowed_header_lower_keys = [k.lower() for k in not_allowed_header_keys]
        if header_key_ in not_allowed_header_lower_keys:
            return True
        return False

    @staticmethod
    def check_read_only_header_in_viewer_request(header_key: str) -> bool:
        read_only_headers = ["Content-Length", "Host", "Transfer-Encoding", "Via"]
        return header_key in read_only_headers

    @staticmethod
    def check_read_only_header_in_origin_request(header_key: str) -> bool:
        read_only_headers = [
            "Accept-Encoding",
            "Content-Length",
            "If-Modified-Since",
            "If-None-Match",
            "If-Range",
            "If-Unmodified-Since",
            "Transfer-Encoding",
            "Via",
        ]
        return header_key in read_only_headers

    @staticmethod
    def check_read_only_header_in_viewer_response(header_key: str) -> bool:
        read_only_headers = ["Content-Length", "Content-Encoding", "Transfer-Encoding", "Warning", "Via"]
        return header_key in read_only_headers

    @staticmethod
    def check_read_only_header_in_origin_response(header_key: str) -> bool:
        read_only_headers = [
            "Transfer-Encoding",
            "Via",
        ]
        return header_key in read_only_headers

    @staticmethod
    def from_key_value(key: str, value: List[Dict[str, str]]):
        value_ = value[0]
        key_ = value[0].get("key", key)
        return CloudFrontLambdaEdgeHeader(key=key_, value=value_["value"])

    @staticmethod
    def from_dict(data: dict) -> List["CloudFrontLambdaEdgeHeader"]:
        return [CloudFrontLambdaEdgeHeader.from_key_value(key=k, value=v) for k, v in data.items()]

    @staticmethod
    def format_to_dict(headers: List["CloudFrontLambdaEdgeHeader"]) -> Dict[str, List[dict]]:
        result: Dict[str, List[dict]] = {}
        for header in headers:
            if header.key in result:
                result[header.key].append({"key": header.key, "value": header.value})
            else:
                result.update(header.format())
        return result

    def format(self) -> dict:
        return {self.key.lower(): [{"key": self.key, "value": self.value}]}


@dataclass(frozen=True)
class CloudFrontLambdaSetCookie:
    key: str
    value: str
    expires: Optional[Union[str, datetime]] = None
    domain: Optional[str] = None
    path: Optional[str] = None
    same_site: str = "Lax"
    secure: bool = True
    http_only: bool = True

    def __post_init__(self):
        assert self.same_site in ["Lax", "Strict", "None"]
        assert type(self.secure) is bool
        assert type(self.http_only) is bool
        if self.expires is not None:
            assert type(self.expires) is str or type(self.expires) is datetime

    def format_value(self) -> str:
        value = f"{self.key}={self.value}"
        if self.expires is not None:
            gmt_format = "%a, %d %b %Y %H:%M:%S GMT"
            if type(self.expires) is str:
                try:
                    _ = datetime.strptime(self.expires, gmt_format)
                except ValueError as e:
                    raise CloudFrontLambdaEdgeError() from e
                value = f"{value}; Expires={self.expires}"
            elif type(self.expires) is datetime:
                value = f"{value}; Expires={self.expires.strftime(gmt_format)}"
        if self.domain is not None:
            value = f"{value}; Domain={self.domain}"
        if self.path is not None:
            value = f"{value}; Path={self.path}"
        if self.same_site is not None:
            value = f"{value}; SameSite={self.same_site}"
        if self.secure:
            value = f"{value}; Secure"
        if self.http_only:
            value = f"{value}; HttpOnly"

        return value


@dataclass(frozen=True)
class CloudFrontLambdaCookie:
    key: str
    value: str

    @staticmethod
    def from_cookie_value(cookie_value: str) -> List["CloudFrontLambdaCookie"]:
        result = []
        cookies = cookie_value.split("; ")
        for cookie in cookies:
            key, value = cookie.split("=")
            result.append(CloudFrontLambdaCookie(key=key, value=value))
        return result


@dataclass(frozen=True)
class CloudFrontLambdaEdgeBody:
    input_truncated: bool = field(metadata={"readonly": True})
    action: str = field(metadata={"readonly": False})
    encoding: str = field(metadata={"readonly": False})
    data: str = field(metadata={"readonly": False})

    @staticmethod
    def from_dict(data: dict):
        return CloudFrontLambdaEdgeBody(
            input_truncated=data["inputTruncated"], action=data["action"], encoding=data["encoding"], data=data["data"]
        )

    def format(self) -> dict:
        return {
            "inputTruncated": self.input_truncated,
            "action": self.action,
            "encoding": self.encoding,
            "data": self.data,
        }


@dataclass(frozen=True)
class CloudFrontLambdaEdgeOrigin:
    custom_headers: list = field(metadata={"readonly": False, "custom_origin": True, "s3_origin": True})
    domain_name: str = field(metadata={"readonly": False, "custom_origin": True, "s3_origin": True})
    path: str = field(metadata={"readonly": False, "custom_origin": True, "s3_origin": True})
    keepalive_timeout: Optional[int] = field(metadata={"readonly": False, "custom_origin": True, "s3_origin": False})
    port: Optional[int] = field(metadata={"readonly": False, "custom_origin": True, "s3_origin": False})
    protocol: Optional[str] = field(metadata={"readonly": False, "custom_origin": True, "s3_origin": False})
    read_timeout: Optional[int] = field(metadata={"readonly": False, "custom_origin": True, "s3_origin": False})
    ssl_protocols: Optional[list] = field(metadata={"readonly": False, "custom_origin": True, "s3_origin": False})
    auth_method: Optional[str] = field(metadata={"readonly": False, "custom_origin": False, "s3_origin": True})
    region: Optional[str] = field(metadata={"readonly": False, "custom_origin": False, "s3_origin": True})

    @staticmethod
    def from_dict(data: dict):
        custom = data["custom"]
        return CloudFrontLambdaEdgeOrigin(
            custom_headers=CloudFrontLambdaEdgeHeader.from_dict(data=custom["customHeaders"]),
            domain_name=custom["domainName"],
            path=custom["path"],
            keepalive_timeout=custom.get("keepaliveTimeout"),
            port=custom.get("port"),
            protocol=custom.get("protocol"),
            read_timeout=custom.get("readTimeout"),
            ssl_protocols=custom.get("sslProtocols"),
            auth_method=custom.get("authMethod"),
            region=custom.get("region"),
        )

    def format(self) -> dict:
        data: Dict[str, Any] = {
            "customHeaders": CloudFrontLambdaEdgeHeader.format_to_dict(self.custom_headers),
            "domainName": self.domain_name,
            "path": self.path,
        }
        if self.keepalive_timeout is not None:
            data.update({"keepaliveTimeout": self.keepalive_timeout})
        if self.port is not None:
            data.update({"port": self.port})
        if self.protocol is not None:
            data.update({"protocol": self.protocol})
        if self.read_timeout is not None:
            data.update({"readTimeout": self.read_timeout})
        if self.ssl_protocols is not None:
            data.update({"sslProtocols": self.ssl_protocols})
        if self.auth_method is not None:
            data.update({"authMethod": self.auth_method})
        if self.region is not None:
            data.update({"region": self.region})
        return {"custom": data}

    def update_custom_header(self, key: str, value: str) -> "CloudFrontLambdaEdgeOrigin":
        self.custom_headers.append(CloudFrontLambdaEdgeHeader(key=key, value=value))
        return replace(self, custom_headers=self.custom_headers)


@dataclass(frozen=True)
class CloudFrontLambdaEdgeRequest:
    body: Optional[CloudFrontLambdaEdgeBody] = field(metadata={"readonly": False})
    client_ip: str = field(metadata={"readonly": True})
    headers: List[CloudFrontLambdaEdgeHeader] = field(metadata={"readonly": False})
    method: str = field(metadata={"readonly": True})
    querystring: str = field(metadata={"readonly": False})
    uri: str = field(metadata={"readonly": False})
    origin: Optional[CloudFrontLambdaEdgeOrigin] = field(metadata={"readonly": False})

    @staticmethod
    def from_dict(data: dict):
        origin = data.get("origin")
        body = data.get("body")
        return CloudFrontLambdaEdgeRequest(
            body=None if body is None else CloudFrontLambdaEdgeBody.from_dict(data=body),
            client_ip=data["clientIp"],
            headers=CloudFrontLambdaEdgeHeader.from_dict(data=data["headers"]),
            method=data["method"],
            querystring=data["querystring"],
            uri=data["uri"],
            origin=None if origin is None else CloudFrontLambdaEdgeOrigin.from_dict(origin),
        )

    def get_header(self, key: str) -> Optional[CloudFrontLambdaEdgeHeader]:
        for header in self.headers:
            if header.key.lower() == key.lower():
                return header
        return None

    def get_cookies(self) -> Optional[List[CloudFrontLambdaCookie]]:
        cookie_header = self.get_header(key="cookie")
        if cookie_header is None:
            return None
        return CloudFrontLambdaCookie.from_cookie_value(cookie_value=cookie_header.value)

    def append_header(self, key: str, value: str, event_type: str) -> "CloudFrontLambdaEdgeRequest":
        if event_type == "viewer-request":
            if CloudFrontLambdaEdgeHeader.check_read_only_header_in_viewer_request(header_key=key):
                raise CloudFrontLambdaEdgeHeaderEditNotAllowedError(header_key=key, event_type=event_type)
        elif event_type == "origin-request":
            if CloudFrontLambdaEdgeHeader.check_read_only_header_in_origin_request(header_key=key):
                raise CloudFrontLambdaEdgeHeaderEditNotAllowedError(header_key=key, event_type=event_type)
        else:
            raise CloudFrontLambdaEdgeHeaderAppendNoEffectError(header_key=key, event_type=event_type)
        self.headers.append(CloudFrontLambdaEdgeHeader(key=key, value=value))
        return replace(self, headers=self.headers)

    def append_custom_header(self, key: str, value: str, event_type: str) -> "CloudFrontLambdaEdgeRequest":
        if event_type == "origin-request":
            if CloudFrontLambdaEdgeHeader.check_allowed_custom_header_key(header_key=key):
                raise CloudFrontLambdaEdgeHeaderEditNotAllowedError(header_key=key, event_type=event_type)
            if self.origin is None:
                raise CloudFrontLambdaEdgeObjectNotFoundError(object_name="origin")
            origin = self.origin.update_custom_header(key=key, value=value)
            return replace(self, origin=origin)
        return self

    def update_querystring(self, querystring: str) -> "CloudFrontLambdaEdgeRequest":
        return replace(self, querystring=querystring)

    def update_uri(self, uri: str) -> "CloudFrontLambdaEdgeRequest":
        if not uri.startswith("/"):
            raise CloudFrontLambdaEdgeError()
        return replace(self, uri=uri)

    def format(self) -> dict:
        data = {
            "clientIp": self.client_ip,
            "headers": CloudFrontLambdaEdgeHeader.format_to_dict(self.headers),
            "method": self.method,
            "querystring": self.querystring,
            "uri": self.uri,
        }
        if self.body is not None:
            data.update({"body": self.body.format()})
        if self.origin is not None:
            data.update({"origin": self.origin.format()})
        return data


@dataclass(frozen=True)
class CloudFrontLambdaEdgeResponse:
    headers: List[CloudFrontLambdaEdgeHeader] = field(metadata={"readonly": False})
    status: str = field(metadata={"readonly": False})
    status_description: str = field(metadata={"readonly": False})

    @staticmethod
    def from_dict(data: dict) -> "CloudFrontLambdaEdgeResponse":
        return CloudFrontLambdaEdgeResponse(
            headers=CloudFrontLambdaEdgeHeader.from_dict(data=data["headers"]),
            status=data["status"],
            status_description=data["statusDescription"],
        )

    def format(self) -> dict:
        return {
            "headers": CloudFrontLambdaEdgeHeader.format_to_dict(self.headers),
            "status": self.status,
            "statusDescription": self.status_description,
        }

    def get_header(self, key: str) -> Optional[CloudFrontLambdaEdgeHeader]:
        for header in self.headers:
            if header.key.lower() == key.lower():
                return header
        return None

    def append_header(self, key: str, value: str, event_type: str) -> "CloudFrontLambdaEdgeResponse":
        if event_type == "viewer-response":
            if CloudFrontLambdaEdgeHeader.check_read_only_header_in_viewer_response(header_key=key):
                raise CloudFrontLambdaEdgeHeaderEditNotAllowedError(header_key=key, event_type=event_type)
        elif event_type == "origin-response":
            if CloudFrontLambdaEdgeHeader.check_read_only_header_in_origin_response(header_key=key):
                raise CloudFrontLambdaEdgeHeaderEditNotAllowedError(header_key=key, event_type=event_type)
        self.headers.append(CloudFrontLambdaEdgeHeader(key=key, value=value))
        return replace(self, headers=self.headers)


@dataclass(frozen=True)
class CloudFrontLambdaEdge:
    config: CloudFrontLambdaEdgeConfig
    request: CloudFrontLambdaEdgeRequest
    response: Optional[CloudFrontLambdaEdgeResponse]

    @staticmethod
    def from_event(event: dict) -> "CloudFrontLambdaEdge":
        if "Records" not in event:
            raise CloudFrontLambdaEdgeError()
        if len(event["Records"]) != 1:
            raise CloudFrontLambdaEdgeError()
        if "cf" not in event["Records"][0]:
            raise CloudFrontLambdaEdgeError()
        return CloudFrontLambdaEdge.from_dict(data=event["Records"][0]["cf"])

    @staticmethod
    def from_dict(data: dict) -> "CloudFrontLambdaEdge":
        response = data.get("response")
        return CloudFrontLambdaEdge(
            config=CloudFrontLambdaEdgeConfig.from_dict(data["config"]),
            request=CloudFrontLambdaEdgeRequest.from_dict(data["request"]),
            response=None if response is None else CloudFrontLambdaEdgeResponse.from_dict(response),
        )

    def format(self) -> dict:
        data = {
            "config": self.config.format(),
            "request": self.request.format(),
        }
        if self.response:
            data.update({"response": self.response.format()})
        return data

    def append_request_header(self, key: str, value: str) -> "CloudFrontLambdaEdge":
        request = self.request.append_header(key=key, value=value, event_type=self.config.event_type)
        return replace(self, request=request)

    def append_request_custom_header(self, key: str, value: str) -> "CloudFrontLambdaEdge":
        request = self.request.append_custom_header(key=key, value=value, event_type=self.config.event_type)
        return replace(self, request=request)

    def update_request_querystring(self, querystring: str) -> "CloudFrontLambdaEdge":
        request = self.request.update_querystring(querystring=querystring)
        return replace(self, request=request)

    def update_request_uri(self, uri: str) -> "CloudFrontLambdaEdge":
        request = self.request.update_uri(uri=uri)
        return replace(self, request=request)

    def add_pseudo_response(self, status: str, status_description: str) -> "CloudFrontLambdaEdge":
        response = CloudFrontLambdaEdgeResponse(headers=[], status=status, status_description=status_description)
        return replace(self, response=response)

    def add_pseudo_redirect_response(
        self, status: str, status_description: str, location_url: str
    ) -> "CloudFrontLambdaEdge":
        response = CloudFrontLambdaEdgeResponse(
            headers=[CloudFrontLambdaEdgeHeader(key="location", value=location_url)],
            status=status,
            status_description=status_description,
        )
        return replace(self, response=response)

    def append_response_header(self, key: str, value: str) -> "CloudFrontLambdaEdge":
        if self.response is None:
            raise CloudFrontLambdaEdgeObjectNotFoundError(object_name="response")
        response = self.response.append_header(key=key, value=value, event_type=self.config.event_type)
        return replace(self, response=response)

    def append_response_set_cookie_header(
        self,
        key: str,
        value: str,
        expires: Optional[Union[str, datetime]] = None,
        domain: Optional[str] = None,
        path: Optional[str] = None,
        same_site: str = "Lax",
        secure: bool = True,
        http_only: bool = True,
    ) -> "CloudFrontLambdaEdge":
        if self.response is None:
            raise CloudFrontLambdaEdgeObjectNotFoundError(object_name="response")
        cookie = CloudFrontLambdaSetCookie(
            key=key,
            value=value,
            expires=expires,
            domain=domain,
            path=path,
            same_site=same_site,
            secure=secure,
            http_only=http_only,
        )
        response = self.response.append_header(
            key="Set-Cookie", value=cookie.format_value(), event_type=self.config.event_type
        )
        return replace(self, response=response)
