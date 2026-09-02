import h11
from pydantic import BaseModel


class Signup(BaseModel):
    email: str


def handle(raw: dict):
    conn = h11.Connection(our_role=h11.CLIENT)
    conn.send(h11.Request(method=b"GET", target=b"/", headers=[]))
    return Signup(**raw)
