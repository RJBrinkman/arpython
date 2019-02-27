#! /usr/bin/env python

from Tkinter import *
import ttk as t
import scan

window = Tk()
window.geometry('400x400')
window.title("ARPython tool")
combo = t.Combobox(window)
combo['values'] = scan.get_interfaces()
combo.current(0)  # set the selected item
combo.grid(column=0, row=0)
window.mainloop()
