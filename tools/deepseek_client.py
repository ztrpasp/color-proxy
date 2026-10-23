"""Minimal DeepSeek Chat Completions client using only the Python standard library."""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Iterator

try:
    from rag_config import DEEPSEEK, DeepSeekSettings
except ImportError:
    from tools.rag_config import DEEPSEEK, DeepSeekSettings  # type: ignore


class DeepSeekError(RuntimeError):
    pass


@dataclass(frozen=True)
class CompletionResult:
    content: str
    model: str
    usage: dict[str, Any]


class DeepSeekClient:
    def __init__(self, settings: DeepSeekSettings = DEEPSEEK) -> None:
        self.settings = settings

    def _payload(self, messages: list[dict[str, str]], stream: bool) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self.settings.model,
            "messages": messages,
            "stream": stream,
            "max_tokens": self.settings.max_tokens,
            "thinking": {"type": "enabled" if self.settings.thinking else "disabled"},
        }
        if not self.settings.thinking:
            payload["temperature"] = self.settings.temperature
        if stream:
            payload["stream_options"] = {"include_usage": True}
        return payload

    def _request(self, messages: list[dict[str, str]], stream: bool):
        if not self.settings.api_key:
            raise DeepSeekError("DEEPSEEK_API_KEY 未配置。请复制 rag.env.example 为 rag.env 并填写 API Key。")
        body = json.dumps(self._payload(messages, stream), ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(
            f"{self.settings.base_url}/chat/completions",
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {self.settings.api_key}",
                "Content-Type": "application/json",
                "Accept": "text/event-stream" if stream else "application/json",
                "User-Agent": "color-proxy-rag/1.0",
            },
        )
        try:
            return urllib.request.urlopen(request, timeout=self.settings.timeout_seconds)
        except urllib.error.HTTPError as exc:
            try:
                detail = exc.read().decode("utf-8", errors="replace")[:2000]
            except Exception:
                detail = ""
            raise DeepSeekError(f"DeepSeek API HTTP {exc.code}: {detail or exc.reason}") from exc
        except urllib.error.URLError as exc:
            raise DeepSeekError(f"无法连接 DeepSeek API: {exc.reason}") from exc

    def complete(self, messages: list[dict[str, str]]) -> CompletionResult:
        response = self._request(messages, False)
        try:
            data = json.loads(response.read().decode("utf-8"))
        except Exception as exc:
            raise DeepSeekError(f"DeepSeek 返回了无法解析的响应: {exc}") from exc
        finally:
            response.close()
        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise DeepSeekError(f"DeepSeek 响应缺少 answer content: {data}") from exc
        return CompletionResult(
            content=str(content or ""),
            model=str(data.get("model") or self.settings.model),
            usage=data.get("usage") if isinstance(data.get("usage"), dict) else {},
        )

    def stream(self, messages: list[dict[str, str]]) -> Iterator[dict[str, Any]]:
        response = self._request(messages, True)
        try:
            for raw in response:
                line = raw.decode("utf-8", errors="replace").strip()
                if not line or not line.startswith("data:"):
                    continue
                payload = line[5:].strip()
                if payload == "[DONE]":
                    break
                try:
                    data = json.loads(payload)
                except ValueError:
                    continue
                usage = data.get("usage")
                if isinstance(usage, dict) and usage:
                    yield {"type": "usage", "usage": usage}
                choices = data.get("choices")
                if not isinstance(choices, list) or not choices:
                    continue
                choice = choices[0]
                delta = choice.get("delta") if isinstance(choice, dict) else None
                if isinstance(delta, dict):
                    content = delta.get("content")
                    if content:
                        yield {"type": "delta", "delta": str(content)}
                finish = choice.get("finish_reason") if isinstance(choice, dict) else None
                if finish:
                    yield {"type": "finish", "finish_reason": str(finish)}
        except OSError as exc:
            raise DeepSeekError(f"读取 DeepSeek SSE 流失败: {exc}") from exc
        finally:
            response.close()
