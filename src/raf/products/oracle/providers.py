"""Oracle reasoning providers.

* ``builtin`` (default) - a deterministic reasoner over retrieved R$F facts; no model, no network.
* ``openai-compatible`` - any server implementing ``POST {base_url}/chat/completions`` (a local
  Ollama/llama.cpp/vLLM server by default, or a hosted service the user configures explicitly).
* ``disabled`` - Oracle is off; the rest of R$F is unaffected.

Providers only turn a prompt into text. They have no tools and cannot change anything; what they
return is validated by :mod:`raf.products.oracle.service` before it is shown.
"""

from __future__ import annotations

import ipaddress
import json
from typing import Protocol
from urllib.parse import urlsplit

import httpx

from raf.core.errors import ConfigError, RafError
from raf.products.oracle.prompt import Prompt

PROVIDERS = ("disabled", "builtin", "openai-compatible")
MAX_RESPONSE_BYTES = 512 * 1024
MAX_ANSWER_CHARS = 20_000


class ProviderError(RafError):
    """The configured model provider could not produce an answer."""

    code = "raf.oracle.provider"
    exit_code = 6
    http_status = 502


class ModelProvider(Protocol):
    name: str
    model: str

    def complete(self, prompt: Prompt) -> str: ...


def is_loopback(url: str) -> bool:
    host = (urlsplit(url).hostname or "").strip("[]").lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def validate_base_url(url: str) -> str:
    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ConfigError(
            f"Invalid oracle.base_url '{url[:200]}'.",
            hint="Use an http(s) URL such as http://127.0.0.1:11434/v1 (raf config set oracle.base_url <url>).",
        )
    if parts.username or parts.password:
        raise ConfigError(
            "oracle.base_url must not contain credentials.",
            hint="Put the API key in RAF_ORACLE_API_KEY or the OS keyring (raf secret set oracle.api_key).",
        )
    return url.strip().rstrip("/")


def transport_warning(url: str) -> str | None:
    parts = urlsplit(url)
    if parts.scheme == "http" and not is_loopback(url):
        return "oracle.base_url uses plain http to a non-loopback host: retrieved workspace data is sent unencrypted"
    return None


class OpenAICompatibleProvider:
    """Chat-completions client. The API key is sent only in the Authorization header and is never
    included in errors, logs or status output."""

    name = "openai-compatible"

    def __init__(
        self,
        base_url: str,
        model: str,
        *,
        api_key: str | None = None,
        timeout: float = 60.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.base_url = validate_base_url(base_url)
        if not model:
            raise ConfigError(
                "oracle.model is not set.", hint="raf config set oracle.model <model name served by the provider>"
            )
        self.model = model
        self._api_key = api_key
        self.timeout = timeout
        self._transport = transport

    def _redact(self, text: str) -> str:
        return text.replace(self._api_key, "[redacted]") if self._api_key else text

    def complete(self, prompt: Prompt) -> str:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        body = {"model": self.model, "messages": prompt.messages(), "temperature": 0, "stream": False}
        url = f"{self.base_url}/chat/completions"
        try:
            with (
                httpx.Client(timeout=self.timeout, transport=self._transport, follow_redirects=False) as client,
                client.stream("POST", url, json=body, headers=headers) as response,
            ):
                raw = bytearray()
                for chunk in response.iter_bytes():
                    raw += chunk
                    if len(raw) > MAX_RESPONSE_BYTES:
                        raise ProviderError("The model provider returned more data than allowed.")
                status = response.status_code
        except httpx.TimeoutException as exc:
            raise ProviderError(
                f"The model provider did not answer within {self.timeout:g} s.",
                hint="Raise oracle.timeout_seconds or use the builtin reasoner (oracle.provider builtin).",
            ) from exc
        except httpx.HTTPError as exc:
            raise ProviderError(
                f"Cannot reach the model provider at {self.base_url}.",
                reason=self._redact(str(exc))[:300],
                hint="Check oracle.base_url and that the server is running, or use the builtin provider.",
            ) from exc
        text = raw.decode("utf-8", "replace")
        if status != 200:
            raise ProviderError(
                f"The model provider answered HTTP {status}.", reason=self._redact(" ".join(text.split()))[:300]
            )
        try:
            data = json.loads(text)
            content = data["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise ProviderError("The model provider returned an unexpected response.") from exc
        if not isinstance(content, str) or not content.strip():
            raise ProviderError("The model provider returned an empty answer.")
        return content[:MAX_ANSWER_CHARS]
