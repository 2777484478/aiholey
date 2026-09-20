"""OpenAI 兼容大模型客户端。

用流式（SSE）拉取并逐块累积：一是避免长响应被中间网关掐断（先前的 "Stream closed"
就是非流式长请求被断的典型症状），二是能把首字节延迟与 token 进度写进日志。
"""
from __future__ import annotations

import json
from typing import Callable, Iterator

import httpx

DEFAULT_TIMEOUT = httpx.Timeout(connect=20.0, read=600.0, write=60.0, pool=20.0)


class LLMError(RuntimeError):
    pass


class LLMClient:
    def __init__(self, base_url: str, api_key: str, model: str, timeout: httpx.Timeout = DEFAULT_TIMEOUT):
        self.base_url = (base_url or "").rstrip("/")
        self.api_key = api_key or ""
        self.model = model
        self.timeout = timeout

    @property
    def url(self) -> str:
        base = self.base_url
        if base.endswith("/chat/completions"):
            return base
        return f"{base}/chat/completions"

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        return h

    def stream(self, messages: list[dict], temperature: float = 0.2,
               max_tokens: int = 4096) -> Iterator[str]:
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": True,
        }
        try:
            with httpx.Client(timeout=self.timeout) as client:
                with client.stream("POST", self.url, headers=self._headers(), json=payload) as resp:
                    if resp.status_code >= 400:
                        body = b"".join(resp.iter_bytes()).decode("utf-8", "ignore")[:600]
                        raise LLMError(f"HTTP {resp.status_code}: {body}")
                    for line in resp.iter_lines():
                        if not line:
                            continue
                        if line.startswith("data:"):
                            line = line[5:].strip()
                        if line == "[DONE]":
                            break
                        try:
                            chunk = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        for ch in chunk.get("choices", []):
                            piece = (ch.get("delta") or {}).get("content")
                            if piece:
                                yield piece
        except httpx.HTTPError as e:
            raise LLMError(f"网络错误：{type(e).__name__}: {e}") from e

    def chat(self, messages: list[dict], temperature: float = 0.2,
             max_tokens: int = 4096, on_progress: Callable[[int], None] | None = None) -> str:
        parts: list[str] = []
        n = 0
        for piece in self.stream(messages, temperature, max_tokens):
            parts.append(piece)
            n += len(piece)
            if on_progress:
                on_progress(n)
        return "".join(parts)

    def test(self) -> tuple[bool, str]:
        try:
            out = self.chat([{"role": "user", "content": "ping, reply with 'pong' only"}], max_tokens=16)
        except LLMError as e:
            return False, str(e)
        return True, (out or "").strip()[:80]


def extract_json(text: str) -> list | dict | None:
    """从模型输出里抠出 JSON（模型常会包 ```json 代码块或加解释性前后缀）。"""
    if not text:
        return None
    t = text.strip()
    if "```" in t:
        import re
        blocks = re.findall(r"```(?:json)?\s*(.+?)```", t, re.S)
        for b in blocks:
            try:
                return json.loads(b.strip())
            except json.JSONDecodeError:
                continue
    try:
        return json.loads(t)
    except json.JSONDecodeError:
        pass
    # 退化路径：截取第一个 [ 或 { 到最后一个配对符号
    for open_ch, close_ch in (("[", "]"), ("{", "}")):
        i, j = t.find(open_ch), t.rfind(close_ch)
        if i != -1 and j > i:
            try:
                return json.loads(t[i:j + 1])
            except json.JSONDecodeError:
                continue
    return None
