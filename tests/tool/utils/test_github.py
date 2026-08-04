from depsafe.tool.utils.github import get_repo_info


class TestGetRepoInfo:
    def test_parses_https_url(self, monkeypatch):
        """HTTPS 格式 → (owner, repo)"""
        monkeypatch.setattr(
            "subprocess.run",
            lambda *a, **kw: type("R", (), {"stdout": "https://github.com/psf/requests.git\n", "stderr": ""})(),
        )
        owner, repo = get_repo_info()
        assert owner == "psf"
        assert repo == "requests"

    def test_parses_ssh_url(self, monkeypatch):
        """SSH 格式 → (owner, repo)"""
        monkeypatch.setattr(
            "subprocess.run",
            lambda *a, **kw: type("R", (), {"stdout": "git@github.com:tiangolo/fastapi.git\n", "stderr": ""})(),
        )
        owner, repo = get_repo_info()
        assert owner == "tiangolo"
        assert repo == "fastapi"
