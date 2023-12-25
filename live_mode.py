from base_page import BasePage
import tkinter as tk
from tkinter import *

class LiveMode(BasePage):
    def __init__(self, root, _):
        super().__init__(root)

        self.root = root
        self.root.title("Live analysis for In-band Network Telemetry")

        self.canvas = Canvas(
            self.root,
            bg = "#D8DEE9",
            height = 1024,
            width = 1440,
            bd = 0,
            highlightthickness = 0,
            relief = "ridge"
        )

        self.canvas.place(x = 0, y = 0)
        self.canvas.create_text(
            533.0,
            73.0,
            anchor="nw",
            text="Live Evaluation",
            fill="#2E3440",
            font=("Inter Bold", 48 * -1)
        )

        self.canvas.create_rectangle(
            332.0,
            216.0,
            1442.0,
            938.0,
            fill="#FFFFFF",
            outline="")

        self.canvas.create_rectangle(
            0.0,
            0.0,
            330.0,
            1024.0,
            fill="#A8A6A6",
            outline="")

        self.canvas.create_rectangle(
            32.0,
            75.0,
            298.0,
            131.0,
            fill="#D9D9D9",
            outline="")

        self.canvas.create_text(
            89.0,
            90.0,
            anchor="nw",
            text="Select Interface",
            fill="#000000",
            font=("Inter Medium", 20 * -1)
        )

        self.canvas.create_rectangle(
            32.0,
            160.0,
            298.0,
            216.0,
            fill="#D9D9D9",
            outline="")

        self.canvas.create_text(
            89.0,
            176.0,
            anchor="nw",
            text="Sniffing Filter",
            fill="#000000",
            font=("Inter Medium", 20 * -1)
        )


if __name__ == "__main__":
    root = tk.Tk()
    LiveMode(root)
    root.mainloop()