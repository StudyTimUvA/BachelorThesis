from index_page import IndexPage
from live_mode import LiveMode
from pcap_mode import PcapMode
from tkinter import *

class MainController:
    def __init__(self):
        self.root = Tk()
        self.frames = {}

        self._add_frame("live_mode", LiveMode)
        self._add_frame("pcap_mode", PcapMode)
        self._add_frame("index_page", IndexPage)

        self.current_frame = None
        self.show_frame("index_page")

    def _add_frame(self, name, frame):
        # TODO: move initialization to show_frame method
        self.frames[name] = frame

    def show_frame(self, name):
        new_frame = self.frames[name](self.root, self)

        if self.current_frame:
            self.current_frame.destroy()

        self.current_frame = new_frame
        self.current_frame.grid(row=0, column=0, sticky="nsew")

    def start(self):
        self.root.mainloop()


if __name__ == "__main__":
    controller = MainController()
    controller.start()