import flask


def health() -> str:
    # 项目 import 了 flask，但从不触碰 session / 请求处理（漏洞触发不可达）
    return flask.__version__
