from base_page import BasePage
import tkinter as tk
from tkinter import *
import numpy as np
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
from matplotlib.figure import Figure
from scapy.all import AsyncSniffer, conf, IP, TCP
import time

conf.iface="lo"

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

        self.plot_figure = Figure(figsize=(10, 10), dpi=100)
        self.plot = self.plot_figure.add_subplot(111)
        self.plot_canvas = FigureCanvasTkAgg(self.plot_figure, master=self.root)
        self.plot_canvas.draw()
        self.plot_canvas.get_tk_widget().place(x=332.0, y=216.0, width=1110.0, height=722.0)

        # self.toolbar = NavigationToolbar2Tk(self.plot_canvas, self.root)
        # self.toolbar.update()
        # self.plot_canvas.get_tk_widget().grid(row=1, column=0, padx=10, pady=10)

        self.plot_canvas.draw()
        
        self.data_points = []

        self.canvas.create_rectangle(
            0.0,
            0.0,
            330.0,
            1024.0,
            fill="#A8A6A6",
            outline="")

        interface_button = tk.Button(
            text="Select Interface",
            font=("Inter Medium", 20 * -1),
            command=self._set_interface
        )
        interface_button.place(
            x=32.0,
            y=75.0,
            width=266.0,
            height=56.0
        )

        sniffing_button = tk.Button(
            text="Sniffing Filter",
            font=("Inter Medium", 20 * -1),
            command=self._set_sniffing_filter
        )
        sniffing_button.place(
            x=32.0,
            y=160.0,
            width=266.0,
            height=56.0
        )
        
        self.sniffer = AsyncSniffer(prn=self.update_plot, store=0)
        self.sniffer.start()

    def _set_interface(self):
        new_interface = tk.simpledialog.askstring(
            title="Select Interface",
            prompt="Enter the name of the interface you want to sniff on:"
        )

        if new_interface is not None:
            self.interface_label.config(text=self.interface)
            conf.iface = self.interface

    def _set_sniffing_filter(self):
        new_sniffing_filter = tk.simpledialog.askstring(
            title="Sniffing Filter",
            prompt="Enter the sniffing filter you want to use:"
        )

        if new_sniffing_filter is not None:
            self.sniffing_filter_label.config(text=self.sniffing_filter)
            self.sniffing_filter = new_sniffing_filter
            # TODO: update sniffing filter
            
    def update_plot(self, packet):
        if not packet.haslayer(IP):
            return

        if not packet.haslayer(TCP):
            # print(f"No TCP layer, {packet[IP].src}>{packet[IP].dst}")
            return

        for option in packet.getlayer(TCP).options:
            if option[0] == 114:
                values = ''.join([hex(x)[2:].zfill(2) for x in option[1]])

                switch_id = int(values[0:4], 16)
                delay = int(values[4:20], 16)

                if switch_id == 0 and delay == 0:
                    continue

                print(f"Switch ID: {switch_id}, delay: {delay}")
                self.data_points.append(delay)
                break

            elif option[0] == 132:
                values = ''.join([hex(x)[2:].zfill(2) for x in option[1]])
                switch_id = int(values[0:4], 16)
                delay = int(values[12:20], 16)

                if switch_id == 0:
                    continue

                print(f"Switch ID: {switch_id}, delay: {delay}")
                self.data_points.append(delay)
                break
            
        if len(self.data_points) % 5 == 0:
            print("Plotting")
            self.plot.clear()
            self.plot.plot(self.data_points, label="Delay")
            print(self.data_points)
            self.plot.legend()
            self.plot_canvas.draw_idle()
            self.plot_canvas.flush_events()
            print("Plotted")

if __name__ == "__main__":
    root = tk.Tk()
    LiveMode(root)
    root.mainloop()