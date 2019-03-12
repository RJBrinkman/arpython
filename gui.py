#! /usr/bin/env python

from Tkinter import *
import ttk as t
import scan

p_x = 10
p_y = 10

# Make the basic TKinter gui
window = Tk()
# window.geometry('400x400')
window.title("ARPython tool")

# Add label for scanning
label_net = t.Label(window, text="Choose the net and interface you want to scan")
label_net.grid(column=0, row=0, stick=W, padx=p_x, pady=p_y)

# Add interface_combobox with interfaces
interface_combo = t.Combobox(window, width=35)
interface_combo['values'] = scan.get_interfaces()
interface_combo.current(0)
interface_combo.grid(column=1, row=0, padx=p_x)


def select_interface(event="x"):
    s = interface_combo.get()
    s = s.split(', ')
    found_ips = scan.scan(net=s[0], interface=s[1])
    found_ips = [', '.join(i[::-1]) for i in found_ips]
    targets_combo['values'] = found_ips
    targets_combo.current(0)
    targets_combo['state'] = 'normal'


# Add scan button
scan_button = t.Button(text="Scan for interfaces", command=select_interface)
scan_button.grid(column=1, row=2, padx=p_x, stick=E)


# Add label for victims
label_victim = t.Label(window, text="Choose your victim")
label_victim.grid(column=0, row=3, stick=W, padx=p_x, pady=p_y)
targets_combo = t.Combobox(window, width=35, state="disabled")
targets_combo.grid(column=1, row=3, padx=p_x)


# Event watcher for when something in the combobox is selected
interface_combo.bind("<<ComboboxSelected>>", select_interface)




# Run Gui
window.mainloop()
