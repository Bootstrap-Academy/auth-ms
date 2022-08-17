from pydantic import BaseModel, Field

from ..utils import example, get_example


USERNAME_REGEX = r"^[a-zA-Z\d]{4,32}$"
EMAIL_REGEX = (  # https://emailregex.com/
    r"""^(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-"""
    r"""\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-"""
    r"""9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a"""
    r"""-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])$"""
)
PASSWORD_REGEX = r"^((?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,})?$"  # noqa: S105
VERIFICATION_CODE_REGEX = r"^([a-zA-Z\d]{4}-){3}[a-zA-Z\d]{4}$"
MFA_CODE_REGEX = r"^\d{6}$"


class User(BaseModel):
    id: str = Field(description="Unique identifier for the user")
    name: str = Field(description="Unique username")
    display_name: str = Field(description="Full name of the user")
    email: str = Field(description="Email address of the user")
    email_verified: bool = Field(description="Whether the user has verified their email address")
    registration: float = Field(description="Timestamp of the user's registration")
    last_login: float | None = Field(description="Timestamp of the user's last successful login")
    enabled: bool = Field(description="Whether the user is enabled")
    admin: bool = Field(description="Whether the user is an administrator")
    password: bool = Field(description="Whether the user has a password (if not, login is only possible via OAuth)")
    mfa_enabled: bool = Field(description="Whether the user has enabled MFA")

    Config = example(
        id="a13e63b1-9830-4604-8b7f-397d2c29955e",
        name="user42",
        display_name="User 42",
        email="user42@example.com",
        email_verified=True,
        registration=1615725447.182818,
        last_login=1615735459.274742,
        enabled=True,
        admin=False,
        password=True,
        mfa_enabled=False,
    )


class UsersResponse(BaseModel):
    total: int = Field(description="Total number of users matching the query")
    users: list[User] = Field(description="Paginated list of users matching the query")

    Config = example(total=1, users=[get_example(User)])


class CreateUser(BaseModel):
    name: str = Field(regex=USERNAME_REGEX, description="Unique username")
    display_name: str = Field(..., min_length=4, max_length=64, description="Full name of the user")
    email: str = Field(..., regex=EMAIL_REGEX, max_length=32, description="Email address of the user")
    password: str | None = Field(regex=PASSWORD_REGEX, description="Password of the user")
    oauth_register_token: str | None = Field(description="OAuth registration token returned by `POST /sessions/oauth`")
    recaptcha_response: str | None = Field(description="Recaptcha response (required if not requested by an admin)")
    enabled: bool = Field(True, description="Whether the user is enabled")
    admin: bool = Field(False, description="Whether the user is an administrator")


class UpdateUser(BaseModel):
    name: str | None = Field(regex=USERNAME_REGEX, description="Change the username")
    display_name: str | None = Field(None, min_length=4, max_length=64, description="Change the user's full name")
    email: str | None = Field(None, regex=EMAIL_REGEX, max_length=32, description="Change the user's email address")
    email_verified: bool | None = Field(None, description="Change whether the user's email address is verified")
    password: str | None = Field(
        regex=PASSWORD_REGEX, description="Change the password (if set to `null`, the password is removed)"
    )
    enabled: bool | None = Field(description="Change whether the user is enabled")
    admin: bool | None = Field(description="Change whether the user is an administrator")
