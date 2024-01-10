"""
This is the main file of the application, and forms the entry point of the application.

The application can be started by running: `sudo python3 main.py`.
The sudo rights are required to capture packets from the network interface in live mode.
The application can be started without sudo rights, but then only pcap files can be used.
"""

from index_page import IndexPage
from live_mode import LiveMode
from pcap_mode import PcapMode
from tkinter import Tk


class MainController:
    """
    This class is the main controller of the application, and is responsible for switching between the different pages.
    When no page is selected, the index page is shown by default.
    """

    def __init__(self):
        self.root = Tk()
        self.frames = {}
        self.settings = {}

        self.define_frame("live_mode", LiveMode)
        self.define_frame("pcap_mode", PcapMode)
        self.define_frame("index_page", IndexPage)

        self.current_frame = None
        self.show_frame("index_page")

    def define_frame(self, name, frame):
        """
        Add a new frame to the list of known frames.

        Args:
            name: The name to use for indexing the frame.
            frame: The class of the frame.
        """
        self.frames[name] = frame

    def show_frame(self, name):
        """
        Show the specified frame.
        This is done by destroying the current frame, and replacing it with the new frame.

        If the specified frame is not known to the controller, an exception is raised.

        Args:
            name: The name of the frame to show.
        """
        frame_class = self.frames.get(name)
        if not frame_class:
            raise Exception(
                f"Frame with name {name} not found in the list of known frames.")

        new_frame = frame_class(self.root, self, self.settings)

        if self.current_frame:
            self.current_frame.destroy()

        self.current_frame = new_frame
        self.current_frame.grid(row=0, column=0, sticky="nsew")

    def start(self):
        self.root.mainloop()


if __name__ == "__main__":
    controller = MainController()
    controller.start()
