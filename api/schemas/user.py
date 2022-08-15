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
    id: str
    name: str
    display_name: str
    email: str
    email_verified: bool
    registration: float
    last_login: float | None
    enabled: bool
    admin: bool
    password: bool
    mfa_enabled: bool

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
    total: int
    users: list[User]

    Config = example(total=1, users=[get_example(User)])


class CreateUser(BaseModel):
    name: str = Field(..., regex=USERNAME_REGEX)
    display_name: str = Field(..., min_length=4, max_length=64)
    email: str = Field(..., regex=EMAIL_REGEX, max_length=32)
    password: str | None = Field(None, regex=PASSWORD_REGEX)
    oauth_register_token: str | None
    recaptcha_response: str | None
    enabled: bool = True
    admin: bool = False


class UpdateUser(BaseModel):
    name: str | None = Field(None, regex=USERNAME_REGEX)
    display_name: str | None = Field(None, min_length=4, max_length=64)
    email: str | None = Field(None, regex=EMAIL_REGEX, max_length=32)
    email_verified: bool | None
    password: str | None = Field(None, regex=PASSWORD_REGEX)
    enabled: bool | None
    admin: bool | None
