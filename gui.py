#! /usr/bin/env python

from Tkinter import *
import ttk as t
import scan

# Make the basic TKinter gui
window = Tk()
window.geometry('400x400')
window.title("ARPython tool")

# Add label for scanning
label_net = t.Label(window, text="Choose the net and interface you want to scan")
label_net.grid(column=0, row=0, sticky=W)

# Add interface_combobox with interfaces
interface_combo = t.Combobox(window, width=35)
interface_combo['values'] = scan.get_interfaces()
interface_combo.current(0)
interface_combo.grid(column=0, row=1, sticky=W)


def select_interface(event="x"):
    s = interface_combo.get()
    s = s.split(', ')
    found_ips = scan.scan(net=s[0], interface=s[1])
    targets_combo['values'] = found_ips
    targets_combo.current(0)


# Add label for victims
label_victim = t.Label(window, text="Choose your victim")
label_victim.grid(column=0, row=3, sticky=W)
targets_combo = t.Combobox(window, width=35)
targets_combo.grid(column=0, row=4, sticky=W)


# Event watcher for when something in the combobox is selected
interface_combo.bind("<<ComboboxSelected>>", select_interface)




# Run Gui
window.mainloop()
