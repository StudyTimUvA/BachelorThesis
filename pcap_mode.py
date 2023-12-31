from base_page import BasePage
import tkinter as tk
from tkinter import *
from tkinter import ttk
import numpy as np
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
from matplotlib.figure import Figure
from PIL import ImageTk, Image
from pandas import DataFrame
from scapy.utils import PcapReader
from scapy import layers

class PcapMode(BasePage):
	def __init__(self, root, controller):
		super().__init__(root)
		self.root = root
		self.root.title("Pcap analysis for In-band Network Telemetry")
  
		self.controller = controller

		self.dataframe = DataFrame()
		self.dataframe_line_attributes = {}

		self.add_pcap_file("tcpdump_logs/dlint_1_flow/5mbps.pcap")
		self.add_pcap_file("tcpdump_logs/dlint_1_flow/20mbps.pcap")

		self.thrash_image = ImageTk.PhotoImage(Image.open("thrash_icon.png").resize((20, 20)))
		self.rename_image = ImageTk.PhotoImage(Image.open("rename_icon.png").resize((20, 20)))

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
			x=5.0,
			y=5.0,
			width=100.0,
			height=50.0
		)

		self.plot_figure = Figure(figsize=(10, 10), dpi=100)
		self.plot = self.plot_figure.add_subplot(111)
		self.plot_canvas = FigureCanvasTkAgg(self.plot_figure, master=self.root)
		self.plot_canvas.draw()
		self.plot_canvas.get_tk_widget().place(x=330.0, y=241.0, width=1110.0, height=722.0)

		# self.toolbar = NavigationToolbar2Tk(self.plot_canvas, self.root)
		# self.toolbar.update()
		# self.plot_canvas.get_tk_widget().grid(row=1, column=0, padx=10, pady=10)

		self.plot.plot([1, 2, 3, 4, 5], [1, 2, 3, 4, 5], label="test")
		self.plot.legend()
		self.plot_canvas.draw()

		self.canvas.create_rectangle(
			0.0,
			0.0,
			330.0,
			1024.0,
			fill="#A8A6A6",
			outline="")

		button_1 = Button(
			text="Select Pcap",
	  		font=("Inter Medium", 20 * -1),
			borderwidth=0,
			highlightthickness=0,
			command=self.select_file_action,
			relief="flat"
		)
		button_1.place(
			x=32.0,
			y=32.0,
			width=266.0,
			height=56.0
		)

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
			# TODO: align buttons
			toggle_button = Checkbutton(self.frame, text=f'{self.dataframe_line_attributes[file]["title"][:30]:<45}',
											variable=self.dataframe_line_attributes[file]["toggle_variable"],
		   									onvalue=True, offvalue=False,
											command=self.update_plot)
			toggle_button.pack(anchor="n")

			# add remove button, with a thrashcan icon
			remove_button = tk.Button(self.frame, image=self.thrash_image, command=lambda file=file: self._remove_line(file))
			remove_button.pack(anchor="n")

			# Add a rename button, with a pencil icon
			rename_button = tk.Button(self.frame, image=self.rename_image, command=lambda file=file: self._rename_line(file))
			rename_button.pack(anchor="n")

	def select_file_action(self):
		file_path = tk.filedialog.askopenfilename(initialdir=".", title="Select file",
													filetypes=(("pcap files", "*.pcap"), ("all files", "*.*")))
		if file_path:
			self.add_pcap_file(file_path)
			self.frame.destroy()
			self.draw_side_menu_elements()
   

	def _remove_line(self, file):
		self.dataframe = self.dataframe.drop(file, axis=1)
		del self.dataframe_line_attributes[file]

	def _rename_line(self, file):
		new_title = tk.simpledialog.askstring("Rename", "Enter new name")
		if new_title is not None:
			self.dataframe_line_attributes[file]["title"] = new_title

	def add_pcap_file(self, file_path):
		self.dataframe[file_path] = ...

		self.dataframe_line_attributes[file_path] = {
			"toggle_variable": BooleanVar(value=False),
			"title": file_path.split("/")[-1],
		}

	def get_values_from_pcap(self, file_path):
		delays = []

		for packet in PcapReader(file_path):
			if packet.getlayer(layers.inet.TCP) is None:
				continue

			for option in packet.getlayer(layers.inet.TCP).options:
				if option[0] == 0x72:
					values = ''.join([hex(x)[2:].zfill(2) for x in option[1]])

					kind = option[0]
					switch_id = int(values[0:4], 16)
					delay = int(values[4:20], 16)

					if switch_id == 0 and delay == 0:
						continue

					delays.append(delay)

				elif option[0] == 0x84:
					values = ''.join([hex(x)[2:].zfill(2) for x in option[1]])

					kind = option[0]
					switch_id = int(values[0:4], 16)
					delay = int(values[12:20], 16)

					if switch_id == 0:
						continue

					delays.append(delay)

		return delays

	def update_plot(self):
		self.plot.clear()

		for file in self.dataframe.columns:
			if self.dataframe_line_attributes[file]["toggle_variable"].get():
				self.plot.plot(self.get_values_from_pcap(file), label=self.dataframe_line_attributes[file]["title"])

		self.plot.legend()
		self.plot_canvas.draw()


if __name__ == "__main__":
	root = tk.Tk()
	PcapMode(root)
	root.mainloop()