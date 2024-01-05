import tkinter as tk
from tkinter import *
from pathlib import Path
import os
from PIL import ImageTk, Image
from base_page import BasePage

def relative_to_assets(path: str) -> Path:
    path = Path(f"{os.getcwd()}/assets/frame0/") / Path(path)
    return path

class IndexPage(BasePage):
    def __init__(self, root, controller, settings):
        super().__init__(root)

        self.root.title("In-band Network Telemetry analysis")
        self.controller = controller
        self.settings = settings

        self.canvas = tk.Canvas(
            self.root,
            bg="#d8dee9",
            height=1024,
            width=1440,
            bd=0,
            highlightthickness=0,
            relief="ridge"
        )

        self.canvas.place(x=0, y=0)

        self.canvas.create_text(
            354.0,
            73.0,
            anchor="nw",
            text="Evaluation Platform For\nIn-Band Network Telemetry Solutions",
            fill="#2E3440",
            font=("Inter Bold", 48 * -1)
        )

        self.icon = ImageTk.PhotoImage(Image.open("assets/pulse.png").resize((100, 100)))
        self.canvas.create_image(
            206.0,
            73.0,
            image=self.icon,
            anchor="nw"
        )

        self.canvas.create_text(
            216.0,
            281.0,
            anchor="nw",
            text="P4 Application:",
            fill="#2E3440",
            font=("Inter SemiBold", 36 * -1)
        )

        self.canvas.create_rectangle(
            506.0,
            281.0,
            973.0,
            325.0,
            fill="#E5E9F0",
            outline="")

        self.selected = StringVar()
        self.selected.set("Delay")
        options = ["Delay", "Path completeness", "Throughput"]
        drop_down = OptionMenu(self.root, self.selected, *options)
        drop_down.place(x=506.0, y=281.0, width=467.0, height=44.0)

        self.canvas.create_rectangle(
            216.0,
            408.0,
            644.0,
            799.0,
            fill="#D8DEE9",
            outline="")

        self.canvas.create_text(
            249.0,
            386.0,
            anchor="nw",
            text="Input Mode",
            fill="#2E3440",
            font=("Inter SemiBold", 36 * -1)
        )

        self.canvas.create_rectangle(
            215.0,
            407.0,
            249.0,
            408.0,
            fill="#000000",
            outline="")

        self.canvas.create_rectangle(
            447.0,
            407.0,
            644.0,
            408.0,
            fill="#000000",
            outline="")

        self.canvas.create_text(
            275.0,
            460.0,
            anchor="nw",
            text="Pcap Files",
            fill="#2E3440",
            font=("Inter Medium", 30 * -1)
        )

        self.canvas.create_text(
            267.0,
            512.0,
            anchor="nw",
            text="Display Results Based On Captured Traffic",
            fill="#000000",
            font=("Inter Medium", 24 * -1)
        )

        self.top_selected = BooleanVar()
        self.top_selected.set(True)
        self.bottom_selected = BooleanVar()
        self.bottom_selected.set(False)
        top_checkbox = Checkbutton(self.root, variable=self.top_selected, command=lambda: self.bottom_selected.set(not self.top_selected.get()))
        top_checkbox.place(x=232.0, y=462.0)

        self.canvas.create_text(
            275.0,
            608.0,
            anchor="nw",
            text="Live Mode",
            fill="#2E3440",
            font=("Inter Medium", 30 * -1)
        )

        self.canvas.create_text(
            267.0,
            663.0,
            anchor="nw",
            text="Display Results Based On Real-Time Traffic",
            fill="#000000",
            font=("Inter Medium", 24 * -1)
        )

        bottom_checkbox = Checkbutton(self.root, variable=self.bottom_selected, command=lambda: self.top_selected.set(not self.bottom_selected.get()))
        bottom_checkbox.place(x=232.0, y=613.0)

        self.next_button_image = ImageTk.PhotoImage(Image.open("assets/next_button.png"))
        self.button_2_image = ImageTk.PhotoImage(Image.open("assets/settings_button.png"))

        button_1 = Button(
            image=self.next_button_image,
            borderwidth=0,
            highlightthickness=0,
            command=self.next_button_action,
            relief="flat"
        )
        button_1.place(
            x=822.0,
            y=456.0,
            width=433.0,
            height=117.0
        )

        button_2 = Button(
            image=self.button_2_image,
            borderwidth=0,
            highlightthickness=0,
            command=lambda: print("button_2 clicked"),
            relief="flat"
        )
        button_2.place(
            x=822.0,
            y=635.0,
            width=433.0,
            height=117.0
        )

    def next_button_action(self):
        self.settings["application"] = self.selected.get()
        
        if self.top_selected.get():
            self.controller.show_frame("pcap_mode")
        else:
            self.controller.show_frame("live_mode")

if __name__ == "__main__":
    root = tk.Tk()
    app = IndexPage(root)
    root.mainloop()
