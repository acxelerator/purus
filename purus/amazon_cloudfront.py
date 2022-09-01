from dataclasses import dataclass, field
from typing import Dict, List, Optional

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
    def is_allowed_custom_header_key(header_key: str) -> bool:
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
        return True

    @staticmethod
    def from_key_value(key: str, value: List[Dict[str, str]]):
        value_ = value[0]
        key_ = value[0].get("key", key)
        return CloudFrontLambdaEdgeHeader(key=key_, value=value_["value"])

    @staticmethod
    def from_dict(data: dict) -> List["CloudFrontLambdaEdgeHeader"]:
        return [CloudFrontLambdaEdgeHeader.from_key_value(key=k, value=v) for k, v in data.items()]

    def format(self) -> dict:
        return {
            self.key.lower(): [{
                "key": self.key,
                "value": self.value
            }]
        }


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
        headers = {}
        for header in self.custom_headers:
            headers.update(header.format())
        data = {
            "customHeaders": headers,
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

    def format(self) -> dict:
        headers = {}
        for header in self.headers:
            headers.update(header.format())
        data = {
            "clientIp": self.client_ip,
            "headers": headers,
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


@dataclass(frozen=True)
class CloudFrontLambdaEdge:
    config: CloudFrontLambdaEdgeConfig
    request: CloudFrontLambdaEdgeRequest
    response: Optional[CloudFrontLambdaEdgeResponse]

    @staticmethod
    def from_dict(data: dict):
        return CloudFrontLambdaEdge(
            config=CloudFrontLambdaEdgeConfig.from_dict(data["config"]),
            request=CloudFrontLambdaEdgeRequest.from_dict(data["request"]),
            response=None,
        )

    def format(self) -> dict:
        return {
            "config": self.config.format(),
            "request": self.request.format(),
        }
