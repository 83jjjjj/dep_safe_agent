from google.protobuf.timestamp_pb2 import Timestamp


def now_ts(seconds: int):
    # CVE-2025-4565 / CVE-2026-0994 触发点：protobuf 反序列化
    ts = Timestamp()
    ts.seconds = seconds
    return ts.SerializeToString()
