import requests


def fetch(url: str, proxies=None):
    # CVE-2023-32681 触发点：带代理的请求可能泄漏 Proxy-Authorization 头
    return requests.get(url, proxies=proxies)
