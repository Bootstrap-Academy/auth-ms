from fastapi import status

from .api_exception import APIException


class UserNotFoundError(APIException):
    status_code = status.HTTP_404_NOT_FOUND
    detail = "User not found"
    description = "This user does not exist."


class UserAlreadyExistsError(APIException):
    status_code = status.HTTP_409_CONFLICT
    detail = "User already exists"
    description = "This user name is already in use."


class EmailAlreadyExistsError(APIException):
    status_code = status.HTTP_409_CONFLICT
    detail = "Email already exists"
    description = "This email is already in use."


class InvalidEmailError(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    detail = "Invalid email"
    description = "This email is invalid."


class EmailNotVerifiedError(APIException):
    status_code = status.HTTP_403_FORBIDDEN
    detail = "Email not verified"
    description = "The email has not been verified."


class EmailAlreadyVerifiedError(APIException):
    status_code = status.HTTP_412_PRECONDITION_FAILED
    detail = "Email already verified"
    description = "The email has already been verified."


class InvalidVerificationCodeError(APIException):
    status_code = status.HTTP_401_UNAUTHORIZED
    detail = "Invalid verification code"
    description = "The verification code is invalid."


class PasswordResetFailedError(APIException):
    status_code = status.HTTP_401_UNAUTHORIZED
    detail = "Password reset failed"
    description = "The email or password reset code is invalid or the reset code has expired."


class MFAAlreadyEnabledError(APIException):
    status_code = status.HTTP_409_CONFLICT
    detail = "MFA already enabled"
    description = "MFA is already enabled."


class MFANotInitializedError(APIException):
    status_code = status.HTTP_412_PRECONDITION_FAILED
    detail = "MFA not initialized"
    description = "MFA has not been initialized."


class InvalidCodeError(APIException):
    status_code = status.HTTP_412_PRECONDITION_FAILED
    detail = "Invalid code"
    description = "This mfa code is invalid or has expired."


class MFANotEnabledError(APIException):
    status_code = status.HTTP_412_PRECONDITION_FAILED
    detail = "MFA not enabled"
    description = "MFA is not enabled."


class NoLoginMethodError(APIException):
    status_code = status.HTTP_412_PRECONDITION_FAILED
    detail = "No login method"
    description = "No login method was provided."


class CannotDeleteLastLoginMethodError(APIException):
    status_code = status.HTTP_403_FORBIDDEN
    detail = "Cannot delete last login method"
    description = "The last login method (password or oauth connection) cannot be deleted."


class RegistrationDisabledError(APIException):
    status_code = status.HTTP_403_FORBIDDEN
    detail = "Registration disabled"
    description = "Registration is disabled."


class OAuthRegistrationDisabledError(APIException):
    status_code = status.HTTP_403_FORBIDDEN
    detail = "OAuth Registration disabled"
    description = "OAuth Registration is disabled."


class RecaptchaError(APIException):
    status_code = status.HTTP_412_PRECONDITION_FAILED
    detail = "Recaptcha failed"
    description = "The ReCaptcha response is invalid."


class NewsletterAlreadySubscribedError(APIException):
    status_code = status.HTTP_409_CONFLICT
    detail = "Newsletter already subscribed"
    description = "The newsletter has already been subscribed to."


class InvalidVatIdError(APIException):
    status_code = status.HTTP_404_NOT_FOUND
    detail = "Invalid VAT ID"
    description = "The vat id is invalid."


class AvatarNotFoundError(APIException):
    status_code = status.HTTP_404_NOT_FOUND
    detail = "No avatar found"
    description = "No avatar found for this user"

class InvalidAvatarTypeError(APIException):
    status_code = status.HTTP_415_UNSUPPORTED_MEDIA_TYPE
    detail = "Unsupported media type"
    description = "This media type isn't supported for avatars"

class AvatarSizeTooLarge(APIException):
    status_code = status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
    detail = "Image is too large"
    description = "The image's size is too large for the avatar"
