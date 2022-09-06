

class CloudFrontLambdaEdgeError(Exception):
    pass


class CloudFrontLambdaEdgeHeaderEditNotAllowedError(CloudFrontLambdaEdgeError):

    def __init__(self, header_key: str, event_type: str):
        super().__init__(f"Not allowed to edit {header_key} at [{event_type}]")
