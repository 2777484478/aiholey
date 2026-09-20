"""Git 仓库操作：连接测试、克隆/拉取到本地。

用 git 子命令而不是 GitPython：少一个依赖，且能精确控制凭据与 SSH Key 的传递方式。
所有调用都禁用交互式提示（GIT_TERMINAL_PROMPT=0），否则凭据错误时 git 会挂住等输入。
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from urllib.parse import quote, urlparse, urlunparse

from backend.config import REPOS_DIR

GIT_TIMEOUT = 600


class GitError(RuntimeError):
    pass


def _inject_credentials(url: str, username: str, password: str) -> str:
    """把用户名/密码（或 Token）嵌进 http(s) URL。

    注意：密码里的 @ : / 等字符必须 URL 编码，否则 URL 会被解析错，git 会连到错误的主机上。
    """
    if not username and not password:
        return url
    p = urlparse(url)
    if p.scheme not in ("http", "https"):
        return url
    user = quote(username or "", safe="")
    pwd = quote(password or "", safe="")
    netloc = f"{user}:{pwd}@{p.hostname}"
    if p.port:
        netloc += f":{p.port}"
    return urlunparse(p._replace(netloc=netloc))


def _mask(url: str) -> str:
    """日志里脱敏，避免把 Token 写进日志文件。"""
    p = urlparse(url)
    if p.username or p.password:
        host = p.hostname or ""
        if p.port:
            host += f":{p.port}"
        return urlunparse(p._replace(netloc=f"***@{host}"))
    return url


def _env(ssh_key: str = "", url: str = "") -> dict:
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_ASKPASS"] = "echo"
    env["LC_ALL"] = "C"
    if ssh_key:
        key = os.path.expanduser(ssh_key)
        env["GIT_SSH_COMMAND"] = (
            f"ssh -i {key} -o IdentitiesOnly=yes -o StrictHostKeyChecking=no "
            f"-o UserKnownHostsFile=/dev/null -o BatchMode=yes"
        )
    # 内网自建 GitLab 常用自签证书
    if url.startswith("https://"):
        env.setdefault("GIT_SSL_NO_VERIFY", "1")
    return env


def _run(args: list[str], cwd: str | None = None, env: dict | None = None,
         timeout: int = GIT_TIMEOUT) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(args, cwd=cwd, env=env, capture_output=True,
                              text=True, timeout=timeout)
    except FileNotFoundError as e:
        raise GitError("系统未找到 git 命令，请先安装 git") from e
    except subprocess.TimeoutExpired as e:
        raise GitError(f"git 操作超时（{timeout}s）") from e


def _tail(text: str, n: int = 800) -> str:
    text = (text or "").strip()
    return text[-n:] if len(text) > n else text


def test_connection(repo: dict) -> tuple[bool, str]:
    """用 ls-remote 验证地址与凭据是否可用。"""
    url = _inject_credentials(repo["url"], repo.get("username", ""), repo.get("password", ""))
    env = _env(repo.get("ssh_key", ""), repo["url"])
    args = ["git", "ls-remote", "--heads", url]
    if repo.get("branch"):
        args.append(repo["branch"])
    try:
        r = _run(args, env=env, timeout=60)
    except GitError as e:
        return False, str(e)
    if r.returncode == 0:
        n = len(r.stdout.strip().splitlines())
        return True, f"连接成功，远端匹配到 {n} 个引用"
    return False, _tail(r.stderr or r.stdout)


def local_path_of(repo_id: int) -> Path:
    return REPOS_DIR / str(repo_id)


def pull(repo: dict, progress=None) -> tuple[bool, str]:
    """把仓库拉到 data/repos/<id>。已存在则 fetch + 强制对齐到远端分支。"""
    def say(msg: str) -> None:
        if progress:
            progress(msg)

    dest = local_path_of(repo["id"])
    url = _inject_credentials(repo["url"], repo.get("username", ""), repo.get("password", ""))
    env = _env(repo.get("ssh_key", ""), repo["url"])
    branch = repo.get("branch") or "main"
    safe_url = _mask(repo["url"])

    if (dest / ".git").exists():
        say(f"仓库已存在，拉取更新：{safe_url} [{branch}]")
        r = _run(["git", "remote", "set-url", "origin", url], cwd=str(dest), env=env, timeout=60)
        if r.returncode != 0:
            say(f"更新远端地址失败：{_tail(r.stderr, 300)}")
        r = _run(["git", "fetch", "--depth", "1", "origin", branch], cwd=str(dest), env=env)
        if r.returncode != 0:
            err = _tail(r.stderr or r.stdout)
            return False, f"拉取失败：{err}"
        r = _run(["git", "checkout", "-f", "-B", branch, "FETCH_HEAD"], cwd=str(dest), env=env, timeout=120)
        if r.returncode != 0:
            return False, f"切换分支失败：{_tail(r.stderr or r.stdout)}"
    else:
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        dest.parent.mkdir(parents=True, exist_ok=True)
        say(f"首次克隆：{safe_url} [{branch}]")
        r = _run(["git", "clone", "--depth", "1", "--single-branch",
                  "--branch", branch, url, str(dest)], env=env)
        if r.returncode != 0:
            err = _tail(r.stderr or r.stdout)
            # 分支不存在时退一步：用默认分支克隆，再尝试切换
            say("指定分支克隆失败，改用默认分支重试")
            r2 = _run(["git", "clone", "--depth", "1", url, str(dest)], env=env)
            if r2.returncode != 0:
                return False, f"克隆失败：{err}"
            r3 = _run(["git", "checkout", branch], cwd=str(dest), env=env, timeout=120)
            if r3.returncode != 0:
                say(f"分支 {branch} 不存在，使用远端默认分支")
                branch = _run(["git", "rev-parse", "--abbrev-ref", "HEAD"],
                              cwd=str(dest), env=env, timeout=30).stdout.strip() or "HEAD"

    head = _run(["git", "log", "-1", "--pretty=%H|%ad|%s", "--date=iso"],
                cwd=str(dest), env=env, timeout=30).stdout.strip()
    size = sum(f.stat().st_size for f in dest.rglob("*") if f.is_file())
    say(f"拉取完成：{head.split('|')[0][:8] if head else '?'} · {size // 1024} KB")
    return True, f"{head}\n本地路径 {dest}"
