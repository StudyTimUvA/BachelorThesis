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
	def __init__(self, root, controller, settings):
		super().__init__(root)

		self.root = root
		self.root.title("Live analysis for In-band Network Telemetry")

		self.controller = controller
		self.settings = settings

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
			conf.iface = self.interface
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
		self.sniffer = AsyncSniffer(prn=self.update_plot, store=0, filter=self.sniffing_filter)
		self.sniffer.start()

	def update_plot(self, packet):
		if not packet.haslayer(IP):
			return

		if not packet.haslayer(TCP):
			# print(f"No TCP layer, {packet[IP].src}>{packet[IP].dst}")
			return

		self.update_values_from_packet(packet)

		if len(self.data_points) % 5 == 0:
			self.plot.clear()
			self.plot.plot(self.data_points, label=self.settings['application'])
			self.plot.legend()
			self.plot_canvas.draw_idle()
			self.plot_canvas.flush_events()

	def update_values_from_packet(self, packet):
		# if self.settings.get("application") == "Delay":
		#     self._update_delay_values_from_packet(packet)

		method_by_setting = {
			"Delay": self._update_delay_values_from_packet,
			"Path completeness": self._update_path_completeness_values,
			"Throughput estimation": self._update_throughput_values
		}

		method = method_by_setting.get(self.settings.get("application"))
		if not method:
			raise Exception(f"No match found for chosen application: {self.settings.get('application')}")

		method(packet)

	def _update_delay_values_from_packet(self, packet):
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

	def _update_path_completeness_values(self, packet):
		...

	def _update_throughput_values(self, packet):
		...