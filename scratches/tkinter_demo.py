
import matplotlib
matplotlib.use('TkAgg')
import numpy as np
from scipy.stats import pearsonr, spearmanr, kendalltau
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
from matplotlib.figure import Figure
# check python version to import correct version of tkinter
import sys
if sys.version_info[0] < 3:
	import Tkinter as Tk
else:
	import tkinter as Tk

class App:
	def __init__(self, root):
		self.root = root
		# create a container for buttons
		buttonFrame = Tk.Frame(root)
		buttonFrame.pack()
		
		self.increment = 0

		# create buttons
		self.buttonGenerate = Tk.Button(master=buttonFrame,
								   text='Generate',
								   command=self.generateMap)
		self.buttonGenerate.pack(side=Tk.LEFT)
		self.buttonQuit = Tk.Button(master=buttonFrame,
							   text='Quit',
							   command=root.destroy)
		self.buttonQuit.pack(side=Tk.LEFT)
		self.buttonAction = Tk.Button(master=buttonFrame,
									text='Action',
									command=self.action)
		self.buttonAction.pack(side=Tk.LEFT)
		
		# create container for text
		textFrame = Tk.Frame(root)
		textFrame.pack()
		
		# create text
		self.label = Tk.Label(master=textFrame,
							  text="Pearson correlation:\nSpearman rho:\nKendall tau:",
							  justify=Tk.LEFT)
		self.label.pack()
		
		# create container for plot
		plotFrame = Tk.Frame(root)
		plotFrame.pack(side=Tk.BOTTOM)
		
		# create plot
		f = Figure(figsize=(5, 4), dpi=100)
		self.ax = f.add_subplot(111)
		self.ax.set_xlim([-0.2, 1.2])
		self.ax.set_ylim([-0.2, 1.2])
		
		self.canvas = FigureCanvasTkAgg(f, master=plotFrame)
		self.canvas.draw()
		self.canvas.get_tk_widget().pack()

		# Create a toolbar and add it to the window
		self.toolbar = NavigationToolbar2Tk(self.canvas, self.root)
		self.toolbar.update()
		self.canvas.get_tk_widget().pack(side=Tk.TOP, fill=Tk.BOTH, expand=True)
	
	def generateMap(self):
		# generate random line
		c = np.random.rand()
		m = np.random.rand() - c
		
		# get data points
		pointCnt = 50
		sigma = np.random.rand()
		x = np.random.rand(pointCnt)
		y = m*x + c + sigma * np.random.randn(pointCnt)
		
		# update text
		corr = pearsonr(x,y)[0]
		rho  = spearmanr(x,y)[0]
		tau  = kendalltau(x,y)[0]
		newVals = """Pearson correlation:\t%.2f\nSpearman rho:\t%.2f\nKendall tau:\t%.2f""" % (corr, rho, tau)
		self.label.config(text=newVals)
		
		# plot points
		self.ax.clear()
		self.ax.scatter(x, y, marker='s', c='black')
		self.ax.scatter(x, y+0.2, c='red')
		
		self.ax.set_xlim([-0.2, 1.2])
		self.canvas.draw()

	def action(self):
		print("action")

		x = np.linspace(-0.2, 1.2, 100)

		for i in range(20):
			self.ax.plot(x, x*(1+self.increment), label='linear')
			self.increment += 0.1

		self.canvas.draw()


root = Tk.Tk()
root.title("Correlation Examples")
app = App(root)
root.mainloop()