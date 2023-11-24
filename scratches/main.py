import matplotlib
matplotlib.use('TkAgg')

import numpy as np
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
from matplotlib.figure import Figure
import tkinter as tk
from dataclasses import dataclass

@dataclass
class PcapFile:
    file_path: str
    toggle_var: tk.BooleanVar
    title: str
    int_type: str

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("In-band Network Telemetry analysis")
        self.root.geometry("1600x900")

        # Create a side menu
        self.side_menu = tk.Frame(root, width=400, bg='grey', relief='raised', bd=2)
        self.side_menu.pack(side='left', fill='both')
        self.side_menu.update()

        demo1 = PcapFile("demo1.pcap", tk.BooleanVar(), "demo1", "DEMO")
        demo2 = PcapFile("demo2.pcap", tk.BooleanVar(), "demo2", "DEMO")
        self.pcap_files = [demo1, demo2]

        self.file_path_selected = None
        self.selected_int_type = None

        # Split side menu into three equal parts
        self.side_menu_height = self.side_menu.winfo_height() / 3
        self._create_top_side_menu()
        self._create_middle_side_menu()
        self._create_bottom_side_menu()

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
        dropdown_options = ["DINT", "PINT"]
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
        print("toggle button pressed")
        for file in self.pcap_files:
            print(file.toggle_var.get())

    def _create_bottom_side_menu(self):
        self.side_menu_bottom = tk.Frame(self.side_menu, width=400, height=self.side_menu_height, bg='grey', relief='raised', bd=2)
        self.side_menu_bottom.pack(side='top', fill='both')



root = tk.Tk()
app = App(root)
root.mainloop()
