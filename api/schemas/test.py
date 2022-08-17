from pydantic import BaseModel, Field

from ..utils import example


class TestResponse(BaseModel):
    result: str = Field(description="Test result")

    Config = example(result="hello world")
