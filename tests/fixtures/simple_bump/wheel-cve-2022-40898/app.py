from wheel.cli import unpack


def install_from_wheel(path: str):
    # CVE-2022-40898 触发点：wheel CLI 解包攻击者可控输入
    unpack(path, dest="dist")
