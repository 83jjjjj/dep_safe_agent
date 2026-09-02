"""pytest 全局配置 & Fixtures 路径注册"""
from pathlib import Path

# Fixtures 根目录
FIXTURES_DIR = Path(__file__).parent / "fixtures"

# 各评估场景路径常量（fixtures 按行为类别分一级目录）
FLASK_CVE_2023_30861 = FIXTURES_DIR / "multi_vuln" / "flask-cve-2023-30861"