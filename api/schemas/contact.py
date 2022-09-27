from pydantic import BaseModel, EmailStr, Field


class Message(BaseModel):
    name: str = Field(max_length=256, description="Full name of the user")
    email: EmailStr = Field(description="Email of the user")
    subject: str = Field(max_length=256, description="Subject of the message")
    message: str = Field(max_length=4096, description="Content of the message")
    recaptcha_response: str | None = Field(description="Recaptcha response")
