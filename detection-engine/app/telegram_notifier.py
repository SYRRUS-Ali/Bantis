"""Small Telegram Bot API sender based on monitor-alert-tool's notifier."""

import json
import urllib.error
import urllib.request


TELEGRAM_API_URL = "https://api.telegram.org/bot{token}/sendMessage"


def send_message(text: str, *, bot_token: str, chat_id: str, timeout: float = 10.0) -> bool:
    """Send one plain text message; return False for any uncertain delivery."""
    request = urllib.request.Request(
        TELEGRAM_API_URL.format(token=bot_token),
        data=json.dumps({"chat_id": chat_id, "text": text}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if response.status != 200:
                return False
            # Telegram's JSON `ok` confirms the Bot API accepted the message.
            payload = json.loads(response.read(65537))
            return isinstance(payload, dict) and payload.get("ok") is True
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError, ValueError, UnicodeError):
        return False