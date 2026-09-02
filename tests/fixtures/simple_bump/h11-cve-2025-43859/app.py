import h11


def make_request(method: bytes = b"GET", target: bytes = b"/"):
    # CVE-2025-43859 触发点：h11 处理请求行
    conn = h11.Connection(our_role=h11.CLIENT)
    conn.send(h11.Request(method=method, target=target, headers=[]))
    return conn.traffic_data()
