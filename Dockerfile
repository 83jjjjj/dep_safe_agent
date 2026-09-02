FROM python:3.12-slim

# 安装 Agent 可能需要的系统工具（如 git，用于 apply_fix_and_verify）
RUN apt-get update && \
    apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*

# 容器以 root 运行，挂载的宿主仓库通常属主为其他 uid，git 默认拒绝操作
RUN git config --system --add safe.directory '*'

# 复制源码并安装 depsafe 及其依赖
WORKDIR /opt/dep_safe_agent
COPY . .
RUN pip install --no-cache-dir .
# pipenv：Pipfile 项目的锁文件再生（apply_fix_and_verify 的 _regenerate_lockfile 需要）
RUN pip install --no-cache-dir pipenv
# uv：pyproject.toml + uv.lock 项目的锁文件再生（_regenerate_lockfile 需要）
RUN pip install --no-cache-dir uv

# Agent 实际操作目标项目的工作目录
WORKDIR /workspace