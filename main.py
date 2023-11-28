import matplotlib
matplotlib.use('TkAgg')

import numpy as np
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
from matplotlib.figure import Figure
import tkinter as tk
from dataclasses import dataclass
import scapy as scapy
from scapy.utils import PcapReader
from scapy import layers

@dataclass
class PcapFile:
	file_path: str
	toggle_var: tk.BooleanVar
	title: str
	int_type: str
	series: np.array = None

class App:
	def __init__(self, root):
		self.root = root
		self.root.title("In-band Network Telemetry analysis")
		self.root.geometry("1600x900")

		self.root.bind_all("q", self.key_pressed)
		self.root.bind_all("esc", self.key_pressed)

		# Create a side menu
		self.side_menu = tk.Frame(root, width=400, bg='grey', relief='raised', bd=2)
		self.side_menu.pack(side='left', fill='both')
		self.side_menu.update()

		demo1 = PcapFile("/home/tim/Desktop/AAUvA/Thesis/tcpdump_logs/dlint_1_flow/5mbps.pcap", tk.BooleanVar(), "dlint 5mbps", "DLINT")
		demo2 = PcapFile("/home/tim/Desktop/AAUvA/Thesis/tcpdump_logs/plint_1_flow/5mbps.pcap", tk.BooleanVar(), "plint 5mbps", "PLINT")
		demo3 = PcapFile("/home/tim/Desktop/AAUvA/Thesis/tcpdump_logs/forw_1_flow/5mbps.pcap", tk.BooleanVar(), "forw 5mbps", "FORW")
		self.pcap_files = [demo1, demo2, demo3]

		self.file_path_selected = None
		self.selected_int_type = None

		# Split side menu into three equal parts
		self.side_menu_height = self.side_menu.winfo_height() / 3
		self._create_top_side_menu()
		self._create_middle_side_menu()
		self._create_bottom_side_menu()

		self._add_plot_to_view()
		# x = np.linspace(0, 2, 100)
		# self.add_to_plot(x, x, label="test")

	def key_pressed(self, event):
		print("key pressed")
		if event.char in ["q", "esc"]:
			self.root.destroy()

	def _create_top_side_menu(self):
		self.side_menu_top = tk.Frame(self.side_menu, width=400, height=self.side_menu_height, bg='grey', relief='raised', bd=2)
		self.side_menu_top.pack(side='top', fill='both')

		# Add a label to the top of the side menu
		label = tk.Label(self.side_menu_top, text="Select a file to analyse", bg='grey')
		label.pack(side='top', pady=10)

		# Add a file selector to the top of the side menu
		self.file_selector_button = tk.Button(self.side_menu_top, text="Select file", command=self.select_file)
		self.file_selector_button.pack(side='top', fill='both', padx=10, pady=10)

		# Add a drop down menu
		dropdown_options = ["DINT", "PINT", "FORW"]
		self.selected_int_type = tk.StringVar(value="Select the type of INT")
		drop_down_menu = tk.OptionMenu(self.side_menu_top, self.selected_int_type, *dropdown_options)
		drop_down_menu.pack(side='top', fill='both', padx=10, pady=10)

		# Create an add button
		add_button = tk.Button(self.side_menu_top, text="Add", command=self.add_pcap_button)
		add_button.pack(side='top', fill='both', padx=40, pady=10)

	def select_file(self):
		self.file_path_selected = tk.filedialog.askopenfilename()
		self.file_selector_button.config(text=self.file_path_selected)
		print(file_path)

	def add_pcap_button(self):
		print("Add button pressed")
		if self.file_path_selected is None:
			print("No file selected")
			return
		if self.selected_int_type.get() == "Select the type of INT":
			print("No INT type selected")
			return

		path = self.file_path_selected
		title = path.split("/")[-1]
		int_type = self.selected_int_type.get()

		self.pcap_files.append(PcapFile(path, tk.BooleanVar(), title, int_type))
		self.redraw_middle_menu_side()

	def _create_middle_side_menu(self):
		self.side_menu_middle = tk.Frame(self.side_menu, width=400, height=self.side_menu_height, bg='grey', relief='raised', bd=2)
		self.side_menu_middle.pack(side='top', fill='both')

		# Add a label to the top of the side menu
		label = tk.Label(self.side_menu_middle, text="toggle captures", bg='grey')
		label.pack(side='top', pady=10)

		# Create toggle buttons for each line
		for line in self.pcap_files:
			toggle_var = tk.BooleanVar()
			toggle_button = tk.Checkbutton(self.side_menu_middle, text=line.title, variable=line.toggle_var, onvalue=True, offvalue=False, bg='grey', command=self.toggle_button)
			toggle_button.pack(anchor='w')

	def redraw_middle_menu_side(self):
		self.side_menu_middle.destroy()
		self.side_menu_bottom.destroy()
		self._create_middle_side_menu()
		self._create_bottom_side_menu()

	def toggle_button(self):
		# Clear the plot
		self.plot.clear()
		self.plot2.clear()

		for file in self.pcap_files:
			if file.toggle_var.get():
				# Draw the file
				if file.series is None:
					delays = self.get_delays_from_pcap(file.file_path)
					file.series = np.array(delays)
				else:
					delays = file.series

				x = np.linspace(0, len(delays), len(delays))
				self.add_to_plot(x, delays, label=file.title)

				print(delays[0:10])

		self.canvas.draw()

	def get_delays_from_pcap(self, pcap_file):
		delays = []
		for packet in PcapReader(pcap_file):
			if packet.getlayer(layers.inet.TCP) is None:
				continue

			for option in packet.getlayer(layers.inet.TCP).options:
				if option[0] == 114:  # hex 0x72
					values = ''.join([hex(x)[2:].zfill(2) for x in option[1]])

					kind = option[0]
					switch_id = int(values[0:4], 16)
					delay = int(values[4:20], 16)

					if switch_id == 0 and delay == 0:
						continue

					delays.append(delay)

				elif option[0] == 132:  # hex 0x84
					# TODO: check this
					values = ''.join([hex(x)[2:].zfill(2) for x in option[1]])

					kind = option[0]
					switch_id = int(values[0:4], 16)
					delay = int(values[12:20], 16)

					if switch_id == 0:
						continue

					delays.append(delay)

		return delays

	def _add_plot_to_view(self):
		# Create a figure
		self.figure = Figure(figsize=(5, 5), dpi=100)
		self.plot = self.figure.add_subplot(121)
		self.plot2 = self.figure.add_subplot(122)

		# Create a canvas
		self.canvas = FigureCanvasTkAgg(self.figure, self.root)
		self.canvas.draw()
		self.canvas.get_tk_widget().pack(side='top', fill='both', expand=True)

		# Create a toolbar
		self.toolbar = NavigationToolbar2Tk(self.canvas, self.root)
		self.toolbar.update()
		self.canvas.get_tk_widget().pack(side='top', fill='both', expand=True)

	def add_to_plot(self, x, y, label=None):
		# if self.radio_options[self.radio_var.get()] == "Delays":
		self.plot.plot(x, y, label=label)
		# elif self.radio_options[self.radio_var.get()] == "ECDF":
		x = np.sort(y)
		y = np.arange(1, len(x) + 1) / len(x)
		self.plot2.plot(x, y, label=label)
		# else:
		# 	print("Unknown radio option")
	
		self.plot.legend()
		self.plot2.legend()
		self.canvas.draw()

	def _create_bottom_side_menu(self):
		self.side_menu_bottom = tk.Frame(self.side_menu, width=400, height=self.side_menu_height, bg='grey', relief='raised', bd=2)
		self.side_menu_bottom.pack(side='top', fill='both')

		# Add radio buttons
		self.radio_options = ["Delays", "ECDF"]
		self.radio_var = tk.IntVar()
		self.radio_var.set(0)

		for i, option in enumerate(self.radio_options):
			radio_button = tk.Radiobutton(self.side_menu_bottom, text=option, variable=self.radio_var, value=i, command=self.radio_button)
			radio_button.pack(anchor='w')

	def radio_button(self):
		print(self.radio_var.get())
		print(self.radio_options[self.radio_var.get()])

root = tk.Tk()
app = App(root)
root.mainloop()
