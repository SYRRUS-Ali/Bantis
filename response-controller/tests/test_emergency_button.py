import sys
from types import SimpleNamespace

import pytest

from emergency_button import show_button


@pytest.mark.parametrize("result, message", [(0, "STOPPED."), (1, "Audit logging failed"), (2, "STOP FAILED")])
def test_button_calls_stop_without_confirmation_and_reports_result(monkeypatch, result, message):
    labels = []
    buttons = []
    calls = []

    class Widget:
        def __init__(self, parent, **kwargs):
            self.options = kwargs

        def pack(self, **kwargs):
            pass

        def config(self, **kwargs):
            self.options.update(kwargs)

    def label(*args, **kwargs):
        widget = Widget(*args, **kwargs)
        labels.append(widget)
        return widget

    def button(*args, **kwargs):
        widget = Widget(*args, **kwargs)
        buttons.append(widget)
        return widget

    window = SimpleNamespace(title=lambda _: None, resizable=lambda *_: None,
                             mainloop=lambda: buttons[0].options["command"]())
    monkeypatch.setitem(sys.modules, "tkinter", SimpleNamespace(Tk=lambda: window, Label=label, Button=button))
    assert show_button(lambda: calls.append("stop") or result) == 0
    assert calls == ["stop"]
    assert message in labels[-1].options["text"]


def test_button_reports_missing_tk_with_cli_fallback(monkeypatch, capsys):
    monkeypatch.setitem(sys.modules, "tkinter", None)
    assert show_button(lambda: pytest.fail("No button was opened")) == 2
    assert "cli.py emergency-stop" in capsys.readouterr().err


def test_button_reports_missing_display_with_cli_fallback(monkeypatch, capsys):
    def no_display():
        raise RuntimeError("no display")

    monkeypatch.setitem(sys.modules, "tkinter", SimpleNamespace(Tk=no_display, TclError=RuntimeError))
    assert show_button(lambda: pytest.fail("No button was opened")) == 2
    assert "cli.py emergency-stop" in capsys.readouterr().err