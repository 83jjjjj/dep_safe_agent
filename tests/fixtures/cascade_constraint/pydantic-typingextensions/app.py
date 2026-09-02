from pydantic import BaseModel


class Signup(BaseModel):
    email: str


def validate(data: dict):
    return Signup(**data)
