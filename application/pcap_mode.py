from base_page import BasePage
import tkinter as tk
from tkinter import Canvas, Frame, BooleanVar, Checkbutton
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
from matplotlib.figure import Figure
from PIL import ImageTk, Image
from pandas import DataFrame
from scapy.utils import PcapReader
from scapy import layers
from plots import assign_plots

EXPECTED_SEQUENCE = [1, 2, 3, 4, 5]


class PcapMode(BasePage):
    def __init__(self, root, controller, settings):
        super().__init__(root)
        self.root = root
        self.root.title("Pcap analysis for In-band Network Telemetry")

        self.controller = controller
        self.settings = settings

        self.dataframe = DataFrame()
        self.dataframe_line_attributes = {}

        self.thrash_image = ImageTk.PhotoImage(
            Image.open("assets/thrash_icon.png").resize((20, 20)))
        self.rename_image = ImageTk.PhotoImage(
            Image.open("assets/rename_icon.png").resize((20, 20)))

        self.canvas = Canvas(
            self.root,
            bg="#D8DEE9",
            height=1024,
            width=1440,
            bd=0,
            highlightthickness=0,
            relief="ridge"
        )

        self.canvas.place(x=0, y=0)
        self.canvas.create_text(
            533.0,
            73.0,
            anchor="nw",
            text="Pcap Evaluation",
            fill="#2E3440",
            font=("Inter Bold", 48 * -1)
        )

        home_page_button = tk.Button(
            text="Home",
            font=("Inter Medium", 20 * -1),
            command=lambda: self.controller.show_frame("index_page")
        )
        home_page_button.place(
            x=32.0,
            y=32.0,
            width=100.0,
            height=56.0
        )

        select_pcap_button = tk.Button(
            text="Select Pcap",
            font=("Inter Medium", 20 * -1),
            command=self.select_file_action,
        )
        select_pcap_button.place(
            x=158.0,
            y=32.0,
            width=140.0,
            height=56.0
        )

        self.plot_figure = Figure(figsize=(10, 10), dpi=100)
        self.plots = assign_plots(self.settings, self.plot_figure)

        self.plot_canvas = FigureCanvasTkAgg(
            self.plot_figure, master=self.root)
        self.plot_canvas.draw()
        self.plot_canvas.get_tk_widget().place(
            x=330.0, y=170.0, width=1110.0, height=722.0)

        self.toolbarFrame = Frame(self.root)
        self.toolbarFrame.place(x=332.0, y=902.0, width=1110.0, height=50.0)
        self.toolbar = NavigationToolbar2Tk(
            self.plot_canvas, self.toolbarFrame)
        self.toolbar.update()

        self.plot_canvas.draw()

        self.canvas.create_rectangle(
            0.0,
            0.0,
            330.0,
            1024.0,
            fill="#A8A6A6",
            outline="")

        self.canvas.create_rectangle(
            -2.0,
            115.0,
            330.0,
            117.0,
            fill="#000000",
            outline="")

        self.draw_side_menu_elements()

    def draw_side_menu_elements(self):
        # Place a frame for the above rectangles
        self.frame = Frame(self.root)
        self.frame.place(x=14.0, y=133.0, width=297.875, height=850.0)

        for file in self.dataframe.columns:
            lineFrame = Frame(self.frame)
            toggle_button = Checkbutton(lineFrame, text=f'{self.dataframe_line_attributes[file]["title"][:30]:<40}',
                                        variable=self.dataframe_line_attributes[file]["toggle_variable"],
                                        onvalue=True, offvalue=False,
                                        command=self.update_plot)
            toggle_button.pack(side="left", anchor="w")

            # add remove button, with a thrashcan icon
            remove_button = tk.Button(
                lineFrame, image=self.thrash_image, command=lambda file=file: self._remove_line(file))
            remove_button.pack(side="left", anchor="w")

            # Add a rename button, with a pencil icon
            rename_button = tk.Button(
                lineFrame, image=self.rename_image, command=lambda file=file: self._rename_line(file))
            rename_button.pack(side="left", anchor="w")
            lineFrame.place(
                x=0.0, y=0.0 + (self.dataframe.columns.get_loc(file) * 50), width=300, height=40.0)

        if len(self.dataframe.columns) == 0:
            # Write text on self.Frame
            text = tk.Label(self.frame, text="No pcap\n selected",
                            font=("Inter Medium", 20 * -1))
            text.place(x=0, y=50, width=300, height=40.0)

    def redraw_middle_menu_side(self):
        self.frame.destroy()
        self.draw_side_menu_elements()

    def select_file_action(self):
        file_path = tk.filedialog.askopenfilename(initialdir=".", title="Select file",
                                                  filetypes=(("pcap files", "*.pcap"), ("all files", "*.*")))
        if file_path:
            self.add_pcap_file(file_path)
            self.redraw_middle_menu_side()

    def _remove_line(self, file):
        self.dataframe = self.dataframe.drop(file, axis=1)
        del self.dataframe_line_attributes[file]
        self.redraw_middle_menu_side()

    def _rename_line(self, file):
        new_title = tk.simpledialog.askstring("Rename", "Enter new name")
        if new_title is not None:
            self.dataframe_line_attributes[file]["title"] = new_title
            self.redraw_middle_menu_side()

    def add_pcap_file(self, file_path):
        self.dataframe[file_path] = ...

        self.dataframe_line_attributes[file_path] = {
            "toggle_variable": BooleanVar(value=False),
            "title": file_path.split("/")[-1],
        }

    def get_values_from_pcap(self, file_path):
        # TODO: Store values in dataframe
        # TODO: Check that the values are not already in the dataframe

        delays = []
        switch_ids = []
        values = {}

        last_time = None

        for packet in PcapReader(file_path):
            if not last_time:
                last_time = packet.time
            else:
                bandwidth = packet.len / (packet.time - last_time)
                last_time = packet.time
                values["Bandwidth"] = values.get("Bandwidth", []) + [bandwidth]
            
            if packet.getlayer(layers.inet.TCP) is None:
                continue

            switch_id, delay = self.get_values_from_packet(packet)

            if switch_id is None or delay is None:
                continue

            if switch_id in EXPECTED_SEQUENCE:
                switch_ids.append(switch_id)
            
            if delay != 0:
                delays.append(delay)

        if self.settings["application"]["Path completeness"]:
            values["Path completeness"] = self.calculate_path_completeness(
                switch_ids)

        if self.settings["application"]["Delay"]:
            values["Delay"] = delays

        window_size = 20
        values["Estimated throughput"] = [sum(values["Bandwidth"][i:i+window_size])/window_size for i in range(0, len(values["Bandwidth"]) - window_size, 1)]
        del values["Bandwidth"]
        return values

    def get_values_from_packet(self, packet):
        switch_id = None
        delay = None

        for option in packet.getlayer(layers.inet.TCP).options:
            if option[0] == 0x72:
                values = ''.join([hex(x)[2:].zfill(2) for x in option[1]])

                switch_id = int(values[0:4], 16)
                delay = int(values[4:20], 16)

                if switch_id == 0 and delay == 0:
                    continue

            elif option[0] == 0x84:
                values = ''.join([hex(x)[2:].zfill(2) for x in option[1]])

                switch_id = int(values[0:4], 16)
                delay = int(values[12:20], 16)

                if switch_id == 0 and delay == 0:
                    continue

        return switch_id, delay

    def calculate_path_completeness(self, values):
        complete_cycles = 0
        broken_cycles = 0
        output = []

        while len(values) > 0:
            if values[0: len(EXPECTED_SEQUENCE)] == EXPECTED_SEQUENCE:
                complete_cycles += 1
                values = values[len(EXPECTED_SEQUENCE):]

            # If not, pop untill the first element in the input array has a lower index than the previous element
            else:
                broken_cycles += 1
                last_num = values.pop(0)

                while len(values) > 0 and EXPECTED_SEQUENCE.index(values[0]) >= EXPECTED_SEQUENCE.index(last_num):
                    last_num = values.pop(0)

            output.append(complete_cycles / (complete_cycles + broken_cycles))

        print(output, complete_cycles, broken_cycles)
        return output

    def update_plot(self):
        for metric in self.plots:
            self.plots[metric].clear()

        for file in self.dataframe.columns:
            if self.dataframe_line_attributes[file]["toggle_variable"].get():
                values = self.get_values_from_pcap(file)

                for metric in values:
                    plot_config = self.settings["plot_config"][metric]

                    if self.settings["plot_config"][metric].get("post_processor"):
                        x, y = self.settings["plot_config"][metric]["post_processor"](
                            values[metric])
                        self.plots[metric].plot(
                            x, y, label=self.dataframe_line_attributes[file]["title"])
                    else:
                        self.plots[metric].plot(
                            values[metric], label=self.dataframe_line_attributes[file]["title"])

                    self.plots[metric].set_title(plot_config.get("title"))
                    self.plots[metric].set_xlabel(plot_config.get("xlabel"))
                    self.plots[metric].set_ylabel(plot_config.get("ylabel"))
                    self.plots[metric].legend()

        self.plot_figure.tight_layout()
        self.plot_canvas.draw_idle()
        self.plot_canvas.flush_events()


if __name__ == "__main__":
    root = tk.Tk()
    PcapMode(root)
    root.mainloop()
