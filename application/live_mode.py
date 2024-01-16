from base_page import BasePage
import tkinter as tk
from tkinter import Canvas, Frame
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
from matplotlib.figure import Figure
from scapy.all import AsyncSniffer, conf, IP, TCP

# Set the default interface
conf.iface = "lo"

# Set a filter for which layers to parse, in this case only TCP and IP to improve performance
conf.layers.filter([TCP, IP])


class LiveMode(BasePage):
    def __init__(self, root, controller, settings):
        super().__init__(root)

        self.root = root
        self.root.title("Live analysis for In-band Network Telemetry")

        self.controller = controller
        self.settings = settings

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
            text="Live Evaluation",
            fill="#2E3440",
            font=("Inter Bold", 48 * -1)
        )

        home_page_button = tk.Button(
            text="Home",
            font=("Inter Medium", 20 * -1),
            command=lambda: self.controller.show_frame("index_page")
        )
        home_page_button.place(
            x=5.0,
            y=5.0,
            width=100.0,
            height=50.0
        )

        self.plot_figure = Figure(figsize=(10, 10), dpi=100)
        if self.settings.get("application") == "Delay":
            self.plot = self.plot_figure.add_subplot(121)
            self.ecdf = self.plot_figure.add_subplot(122)
        else:
            self.plot = self.plot_figure.add_subplot(111)

        self.plot_canvas = FigureCanvasTkAgg(
            self.plot_figure, master=self.root)
        self.plot_canvas.draw()
        self.plot_canvas.get_tk_widget().place(
            x=332.0, y=170.0, width=1110.0, height=725.0)

        self.toolbarFrame = Frame(self.root)
        self.toolbarFrame.place(x=332.0, y=902.0, width=1110.0, height=50.0)
        self.toolbar = NavigationToolbar2Tk(
            self.plot_canvas, self.toolbarFrame)
        self.toolbar.update()

        self.plot_canvas.draw()

        # Data points for the plot
        self.data_points = []

        # Variables for tracking path completeness
        self.complete_cycles_per_port = {}
        self.broken_cycles_per_port = {}
        self.id_input_array_per_port = {}
        self.expected_sequence = [1, 2, 3, 4]
        self.every_other = False

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

        reset_button = tk.Button(
            text="Reset",
            font=("Inter Medium", 20 * -1),
            command=self._reset_data
        )
        reset_button.place(
            x=32.0,
            y=245.0,
            width=266.0,
            height=56.0
        )

        if self.settings.get("application") == "Delay":
            ecdf_button = tk.Button(
                text="Generate ECDF",
                font=("Inter Medium", 20 * -1),
                command=self.generate_ecdf
            )
            ecdf_button.place(
                x=32.0,
                y=330.0,
                width=266.0,
                height=56.0
            )

        self.sniffing_filter = ""
        self.sniffer = AsyncSniffer(prn=self.update_plot, store=0)
        self.sniffer.start()

    def _set_interface(self):
        new_interface = tk.simpledialog.askstring(
            title="Select Interface",
            prompt="Enter the name of the interface you want to sniff on:",
            initialvalue=conf.iface
        )

        if new_interface is not None:
            conf.iface = new_interface
            self.restart_sniffer()

    def _set_sniffing_filter(self):
        new_sniffing_filter = tk.simpledialog.askstring(
            title="Sniffing Filter",
            prompt="Enter the sniffing filter you want to use:",
            initialvalue=self.sniffing_filter
        )

        if new_sniffing_filter is not None:
            self.sniffing_filter = new_sniffing_filter
            self.restart_sniffer()

    def _reset_data(self):
        self.data_points = []
        self.plot.clear()
        self.plot_canvas.draw_idle()
        self.plot_canvas.flush_events()

    def restart_sniffer(self):
        self.sniffer.stop()
        self.sniffer = AsyncSniffer(
            prn=self.update_plot, store=0, filter=self.sniffing_filter)
        self.sniffer.start()

    def update_plot(self, packet):
        if not packet.haslayer(TCP):
            return

        self.update_values_from_packet(packet)

        if len(self.data_points) % 5 == 0 and len(self.data_points) > 0:
            self.plot.clear()
            self.plot.plot(self.data_points,
                           label=self.settings['application'])
            self.plot.set_xlabel("Packet #")
            # self.plot.title = self.settings['application']
            self.plot.legend()
            self.plot_canvas.draw_idle()
            self.plot_canvas.flush_events()

    def update_values_from_packet(self, packet):
        method_by_setting = {
            "Delay": self._update_delay_values_from_packet,
            "Path completeness": self._update_path_completeness_values,
            "Throughput estimation": self._update_throughput_values
        }

        method = method_by_setting.get(self.settings.get("application"))
        if not method:
            raise Exception(
                f"No match found for chosen application: {self.settings.get('application')}")

        method(packet)

    def _update_delay_values_from_packet(self, packet):
        delay = -1

        for option in packet.getlayer(TCP).options:
            if option[0] == 114:
                values = ''.join([hex(x)[2:].zfill(2) for x in option[1]])

                switch_id = int(values[0:4], 16)
                delay = int(values[4:20], 16)

                if switch_id == 0 and delay == 0:
                    continue

                break

            elif option[0] == 132:
                values = ''.join([hex(x)[2:].zfill(2) for x in option[1]])
                switch_id = int(values[0:4], 16)
                delay = int(values[12:20], 16)

                if switch_id == 0 and delay == 0:
                    continue

                break

        if delay <= 0:
            return

        self.data_points.append(delay)

    def _update_path_completeness_values(self, packet):
        switch_id = -1

        if self.every_other:
            self.every_other != self.every_other
            return

        for option in packet.getlayer(TCP).options:
            if option[0] == 114:
                values = ''.join([hex(x)[2:].zfill(2) for x in option[1]])

                switch_id = int(values[0:4], 16)
            elif option[0] == 132:
                values = ''.join([hex(x)[2:].zfill(2) for x in option[1]])
                switch_id = int(values[0:4], 16)

        if switch_id == -1:
            return

        dport = packet.getlayer(TCP).dport
        if switch_id in self.expected_sequence:
            self.id_input_array_per_port[dport] = self.id_input_array_per_port.get(
                dport, []) + [switch_id]
        else:
            print(f"Received packet with unexpected switch ID: {switch_id}")

        id_input_array = self.id_input_array_per_port.get(dport, [])
        if len(id_input_array) < len(self.expected_sequence) + 2:
            print(
                f"Broken: {self.broken_cycles_per_port}, Complete: {self.complete_cycles_per_port}")
            return

        # Make sure the port is in the dictionaries
        self.broken_cycles_per_port[dport] = self.broken_cycles_per_port.get(
            dport, 0)
        self.complete_cycles_per_port[dport] = self.complete_cycles_per_port.get(
            dport, 0)

        while len(id_input_array) > len(self.expected_sequence):
            # Check if the first elements in the input array matches the expected sequence
            if id_input_array[0: len(self.expected_sequence)] == self.expected_sequence:
                self.complete_cycles_per_port[dport] += 1
                id_input_array = id_input_array[len(self.expected_sequence):]

            # If not, pop untill the first element in the input array has a lower index than the previous element
            else:
                self.broken_cycles_per_port[dport] += 1
                last_num = id_input_array.pop(0)
                while len(id_input_array) > 0 \
                        and self.expected_sequence.index(id_input_array[0]) >= self.expected_sequence.index(last_num):
                    last_num = id_input_array.pop(0)

        total_complete_cycles = sum(self.complete_cycles_per_port.values())
        total_broken_cycles = sum(self.broken_cycles_per_port.values())
        self.data_points.append(
            total_complete_cycles / (total_complete_cycles + total_broken_cycles))

    def _update_throughput_values(self, packet):
        ...

    def generate_ecdf(self):
        if not self.settings.get("application") == "Delay":
            return

        self.ecdf.clear()
        self.ecdf.hist(self.data_points, cumulative=True,
                       density=True, bins=1000, histtype='step', label='ECDF')
        self.ecdf.set_xlabel("Delay (ns)")
        self.ecdf.set_ylabel("ECDF")
        self.ecdf.set_title("ECDF")
        self.ecdf.legend()
        self.plot_canvas.draw_idle()
        self.plot_canvas.flush_events()
