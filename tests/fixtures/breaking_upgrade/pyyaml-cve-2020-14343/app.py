import yaml


def parse_config(raw: str):
    # CVE-2020-14343 触发点：不带 Loader 的不安全加载
    return yaml.load(raw)
