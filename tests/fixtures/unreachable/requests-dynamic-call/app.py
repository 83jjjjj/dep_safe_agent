import requests


def fetch(url: str, method: str = "get"):
    # 动态调用：属性名来自函数参数，静态分析无法确定实际调用目标
    func = getattr(requests, method)
    return func(url)
