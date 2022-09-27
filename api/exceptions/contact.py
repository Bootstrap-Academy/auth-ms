from fastapi import status

from .api_exception import APIException


class CouldNotSendMessageError(APIException):
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    detail = "Could not send message"
    description = "The message could not be sent."
