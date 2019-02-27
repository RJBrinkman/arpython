#! /usr/bin/env python

from Tkinter import *
import ttk as t
import scan


def callbackFunc(event):
    print("")

# Make the basic TKinter gui
window = Tk()
window.geometry('400x400')
window.title("ARPython tool")

# Add label for scanning
labelTop = t.Label(window, text="Choose the net and interface you want to scan")
labelTop.grid(column=0, row=0)

# Add combobox with interfaces
combo = t.Combobox(window)
combo['values'] = scan.get_interfaces()
combo.current(0)
combo.grid(column=0, row=1)

combo.bind("<<ComboboxSelected>>", callbackFunc)

# Run Gui
window.mainloop()
