from __future__ import annotations

import http.client
import ipaddress
import json
import re
import urllib.parse

DEFAULT_API_URL = "https://api.github.com"
_REPO = re.compile(r"^[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}$")
_VARIABLE = re.compile(r"^[A-Z][A-Z0-9_]{0,99}$")
_ERROR_BODY_LIMIT = 200


class GitHubError(RuntimeError):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(f"GitHub API returned HTTP {status}: {message}")
        self.status = status


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class GitHubVariables:
    def __init__(self, repo: str, token: str, api_url: str = DEFAULT_API_URL, timeout: float = 10.0) -> None:
        if not _REPO.match(repo):
            raise ValueError(f"repository must look like owner/name, got {repo!r}")
        if not token or not token.strip():
            raise ValueError("a GitHub token is required")
        parsed = urllib.parse.urlparse(api_url)
        if parsed.scheme != "https" and not (parsed.scheme == "http" and _is_loopback(parsed.hostname or "")):
            raise ValueError(f"the GitHub API URL must be https, got {api_url!r}")
        self.repo = repo
        self._token = token
        self._https = parsed.scheme == "https"
        self._host = parsed.hostname
        self._port = parsed.port or (443 if self._https else 80)
        self._base = parsed.path.rstrip("/")
        self._timeout = timeout

    def __repr__(self) -> str:  # never let the token reach a log line
        return f"GitHubVariables(repo={self.repo!r})"

    def _request(self, method: str, path: str, body: dict | None = None) -> tuple[int, dict | None]:
        connection_cls = http.client.HTTPSConnection if self._https else http.client.HTTPConnection
        connection = connection_cls(self._host, self._port, timeout=self._timeout)
        headers = {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "bantis-response-controller",
        }
        payload = None
        if body is not None:
            payload = json.dumps(body)
            headers["Content-Type"] = "application/json"
        try:
            connection.request(method, f"{self._base}{path}", body=payload, headers=headers)
            response = connection.getresponse()
            raw = response.read()
        except (OSError, http.client.HTTPException) as exc:
            raise GitHubError(0, f"{method} {path} failed: {type(exc).__name__}") from None
        finally:
            connection.close()
        data = None
        if raw:
            try:
                data = json.loads(raw)
            except ValueError:
                data = {"message": raw[:_ERROR_BODY_LIMIT].decode("utf-8", "replace")}
        return response.status, data

    def _path(self, name: str | None = None) -> str:
        base = f"/repos/{self.repo}/actions/variables"
        if name is None:
            return base
        if not _VARIABLE.match(name):
            raise ValueError(f"invalid variable name {name!r}")
        return f"{base}/{name}"

    @staticmethod
    def _fail(status: int, data: dict | None) -> GitHubError:
        message = str((data or {}).get("message", ""))[:_ERROR_BODY_LIMIT]
        return GitHubError(status, message or "no message")

    def get(self, name: str) -> str | None:
        status, data = self._request("GET", self._path(name))
        if status == 404:
            return None
        if status != 200 or not isinstance(data, dict) or not isinstance(data.get("value"), str):
            raise self._fail(status, data)
        return data["value"]

    def create(self, name: str, value: str) -> bool:
        """True if created; False if it already existed (409)."""
        status, data = self._request("POST", self._path(), {"name": name, "value": value})
        if status == 201:
            return True
        if status == 409:
            return False
        raise self._fail(status, data)

    def delete(self, name: str) -> bool:
        """True if deleted; False if it didn't exist. Either way it's gone."""
        status, data = self._request("DELETE", self._path(name))
        if status == 204:
            return True
        if status == 404:
            return False
        raise self._fail(status, data)