from pydantic import BaseModel, EmailStr, Field

from ..utils.docs import example, get_example


USERNAME_REGEX = r"^[a-zA-Z\d]{4,32}$"
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
    description: str | None = Field(description="Description of the user")
    tags: list[str] = Field(description="Tags for the user")

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
        description="This is a test user",
        tags=["test", "foo", "bar"],
    )


class UsersResponse(BaseModel):
    total: int = Field(description="Total number of users matching the query")
    users: list[User] = Field(description="Paginated list of users matching the query")

    Config = example(total=1, users=[get_example(User)])


class CreateUser(BaseModel):
    name: str = Field(regex=USERNAME_REGEX, description="Unique username")
    display_name: str = Field(..., min_length=4, max_length=64, description="Full name of the user")
    email: EmailStr = Field(..., description="Email address of the user")
    password: str | None = Field(regex=PASSWORD_REGEX, description="Password of the user")
    oauth_register_token: str | None = Field(description="OAuth registration token returned by `POST /sessions/oauth`")
    recaptcha_response: str | None = Field(description="Recaptcha response (required if not requested by an admin)")
    enabled: bool = Field(True, description="Whether the user is enabled")
    admin: bool = Field(False, description="Whether the user is an administrator")


class UpdateUser(BaseModel):
    name: str | None = Field(regex=USERNAME_REGEX, description="Change the username")
    display_name: str | None = Field(None, min_length=4, max_length=64, description="Change the user's full name")
    email: EmailStr | None = Field(None, description="Change the user's email address")
    email_verified: bool | None = Field(None, description="Change whether the user's email address is verified")
    password: str | None = Field(
        regex=PASSWORD_REGEX, description="Change the password (if set to `null`, the password is removed)"
    )
    enabled: bool | None = Field(description="Change whether the user is enabled")
    admin: bool | None = Field(description="Change whether the user is an administrator")
    description: str | None = Field(max_length=1024, description="Change the user's description")
    tags: list[str] | None = Field(max_items=8, max_length=64, description="Change the user's tags")


class RequestPasswordReset(BaseModel):
    email: EmailStr = Field(description="The email address of the user to reset the password for")
    recaptcha_response: str | None = Field(description="Recaptcha response (required if enabled)")


class ResetPassword(BaseModel):
    email: EmailStr = Field(description="Email address of the user")
    code: str = Field(regex=VERIFICATION_CODE_REGEX, description="Password reset code")
    password: str = Field(regex=PASSWORD_REGEX, description="New password for the user")
