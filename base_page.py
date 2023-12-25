import tkinter as tk

class BasePage(tk.Frame):
    def __init__(self, root):
        super().__init__(root)

        self.root = root
        self.root.geometry("1440x1024")
        self.root.configure(background="#d8dee9")

        self.root.bind_all("q", self.key_pressed)

    def key_pressed(self, event):
        if event.char == "q":
            self.root.destroy()