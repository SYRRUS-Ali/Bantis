"""Local operator control; no network listener or approval prompt."""

from __future__ import annotations

import sys
from collections.abc import Callable


def show_button(stop: Callable[[], int]) -> int:
    try:
        import tkinter as tk
    except ImportError:
        print("The emergency button requires Tk. Use cli.py emergency-stop instead.", file=sys.stderr)
        return 2
    try:
        window = tk.Tk()
    except tk.TclError as exc:
        print(f"Could not open emergency button: {exc}. Use cli.py emergency-stop instead.", file=sys.stderr)
        return 2

    window.title("Bantis emergency stop")
    window.resizable(False, False)
    tk.Label(window, text="Stop all response execution and AI model calls.", padx=24, pady=16).pack()
    status = tk.Label(window, text="Ready. Stopping requires no approval.", wraplength=420, padx=24, pady=16)

    def engage() -> None:
        result = stop()
        messages = {
            0: "STOPPED. Execution and AI calls are disabled.",
            1: "STOPPED. Audit logging failed; check the terminal for details.",
        }
        status.config(text=messages.get(result, "STOP FAILED. Check the terminal and state directory permissions. Retry immediately."))

    tk.Button(window, text="EMERGENCY STOP", command=engage, bg="#b91c1c", fg="white",
              activebackground="#991b1b", activeforeground="white", font=("Arial", 20, "bold"),
              padx=24, pady=20).pack(padx=24)
    status.pack()
    window.mainloop()
    return 0