class CloudFrontLambdaEdgeError(Exception):
    pass


class CloudFrontLambdaEdgeObjectNotFoundError(CloudFrontLambdaEdgeError):
    def __init__(self, object_name: str):
        super().__init__(f"Not found [{object_name}]")


class CloudFrontLambdaEdgeHeaderEditNotAllowedError(CloudFrontLambdaEdgeError):
    def __init__(self, header_key: str, event_type: str):
        super().__init__(f"Not allowed to edit {header_key} at [{event_type}]")


class CloudFrontLambdaEdgeHeaderAppendNoEffectError(CloudFrontLambdaEdgeError):
    def __init__(self, header_key: str, event_type: str):
        super().__init__(f"No effect to append {header_key} at [{event_type}]")
