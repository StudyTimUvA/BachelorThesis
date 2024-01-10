"""
This file forms the base of a page in the application.

It sets the background color, and the resolution of the window.
It also also defines 'q' to quit the application.
"""

import tkinter as tk


class BasePage(tk.Frame):
    def __init__(self, root):
        super().__init__(root)

        self.root = root
        self.root.geometry("1440x1024")
        self.root.configure(background="#d8dee9")

        self.root.bind_all("q", self.quit)

    def quit(self, _):
        self.root.destroy()
