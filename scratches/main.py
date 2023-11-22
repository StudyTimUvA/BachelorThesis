import matplotlib
matplotlib.use('TkAgg')

import numpy as np
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
from matplotlib.figure import Figure
import tkinter as tk

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("In-band Network Telemetry analysis")
        self.root.geometry("1600x900")

        # Create a side menu
        self.side_menu = tk.Frame(root, width=400, bg='grey', relief='raised', bd=2)
        self.side_menu.pack(side='left', fill='both')
        self.side_menu.update()

        self.dumps_elements = ['aaaaaaaaaa', 'bbbbbbbbbbbbbbb']

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
        drop_down_menu = tk.OptionMenu(self.side_menu_top, tk.StringVar(value="Select the type of INT"), *dropdown_options)
        drop_down_menu.pack(side='top', fill='both', padx=10, pady=10)

        # Create an add button
        add_button = tk.Button(self.side_menu_top, text="Add", command=self.add_pcap_button)
        add_button.pack(side='top', fill='both', padx=40, pady=10)

    def select_file(self):
        file_path = tk.filedialog.askopenfilename()
        self.file_selector_button.config(text=file_path)
        print(file_path)

    def add_pcap_button(self):
        print("Add button pressed")
        self.dumps_elements.append("new element")
        self.redraw_middle_menu_side()

    def _create_middle_side_menu(self):
        self.side_menu_middle = tk.Frame(self.side_menu, width=400, height=self.side_menu_height, bg='grey', relief='raised', bd=2)
        self.side_menu_middle.pack(side='top', fill='both')

        # Add a label to the top of the side menu
        label = tk.Label(self.side_menu_middle, text="toggle captures", bg='grey')
        label.pack(side='top', pady=10)

        # Create toggle buttons for each line
        self.toggle_vars = []
        for line in self.dumps_elements:
            toggle_var = tk.BooleanVar()
            toggle_button = tk.Checkbutton(self.side_menu_middle, text=line, variable=toggle_var, onvalue=True, offvalue=False, bg='grey', command=self.toggle_button)
            toggle_button.pack(anchor='w')
            self.toggle_vars.append(toggle_var)

    def redraw_middle_menu_side(self):
        self.side_menu_middle.destroy()
        self.side_menu_bottom.destroy()
        self._create_middle_side_menu()
        self._create_bottom_side_menu()

    def toggle_button(self):
        print("toggle button pressed")
        for val in self.toggle_vars:
            print(val.get())

    def _create_bottom_side_menu(self):
        self.side_menu_bottom = tk.Frame(self.side_menu, width=400, height=self.side_menu_height, bg='grey', relief='raised', bd=2)
        self.side_menu_bottom.pack(side='top', fill='both')



root = tk.Tk()
app = App(root)
root.mainloop()
