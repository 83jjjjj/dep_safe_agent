from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route


async def homepage(request):
    # CVE 系列触发点：starlette 处理请求
    return JSONResponse({"ok": True})


app = Starlette(routes=[Route("/", homepage)])
