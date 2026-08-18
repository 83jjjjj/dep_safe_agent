FROM python:3.12-slim

# 安装 Agent 可能需要的系统工具（如 git，用于 apply_fix_and_verify）
RUN apt-get update && \
    apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*

# 复制源码并安装 depsafe 及其依赖
WORKDIR /opt/dep_safe_agent
COPY . .
RUN pip install --no-cache-dir .

# Agent 实际操作目标项目的工作目录
WORKDIR /workspace