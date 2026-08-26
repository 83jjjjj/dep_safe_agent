import re
import subprocess


def get_repo_info() -> tuple[str, str]:
    """
    通过 git remote -v 解析当前项目的 owner 和 repo。
    支持 SSH (git@github.com:owner/repo.git) 和 HTTPS (https://github.com/owner/repo.git) 两种格式。

    Returns:
        (owner, repo) 元组

    Raises:
        RuntimeError: 无法解析仓库信息时抛出
    """
    try:
        result = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            capture_output=True,
            text=True,
            check=True,
        )
        url = result.stdout.strip()
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to get git remote URL: {e.stderr.strip()}")
    ssh_match = re.match(r"git@github\.com:([^/]+)/([^/.]+)(\.git)?$", url)
    if ssh_match:
        return ssh_match.group(1), ssh_match.group(2)
    # 容忍 setup_eval_env.sh 写入的内联认证 URL（https://x-access-token:TOKEN@github.com/owner/repo.git）
    https_match = re.match(r"https://(?:[^@/]+@)?github\.com/([^/]+)/([^/.]+)(\.git)?$", url)
    if https_match:
        return https_match.group(1), https_match.group(2)
    raise RuntimeError(f"Cannot parse owner/repo from remote URL: {url}")
