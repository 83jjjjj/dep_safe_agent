from pydantic import BaseModel


class UserSignup(BaseModel):
    email: str
    name: str


def validate_signup(data: dict):
    # CVE-2024-3772 触发点：用 pydantic 校验用户输入的邮箱字符串
    return UserSignup(**data)
