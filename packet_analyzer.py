from scapy.all import sniff, hexdump
from scapy.layers.inet import IP
import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext
import threading

class PacketSniffer:
    def __init__(self, master):
        self.master = master
        self.master.title("Network Packet Analyzer")
        self.master.geometry("900x600")

        # Create Treeview
        self.tree = ttk.Treeview(master)
        self.tree['columns'] = ('Source', 'Destination', 'Protocol', 'Payload')
        self.tree.column('#0', width=0, stretch=tk.NO)
        self.tree.column('Source', anchor=tk.W, width=120)
        self.tree.column('Destination', anchor=tk.W, width=120)
        self.tree.column('Protocol', anchor=tk.W, width=100)
        self.tree.column('Payload', anchor=tk.W, width=500)

        self.tree.heading('#0', text='', anchor=tk.W)
        self.tree.heading('Source', text='Source Address', anchor=tk.W)
        self.tree.heading('Destination', text='Destination Address', anchor=tk.W)
        self.tree.heading('Protocol', text='Protocol', anchor=tk.W)
        self.tree.heading('Payload', text='Payload', anchor=tk.W)

        self.tree.pack(pady=20)

        self.tree.bind("<Double-1>", self.on_double_click)

        self.start_button = tk.Button(master, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(pady=10)

        self.stop_button = tk.Button(master, text="Stop Sniffing", command=self.stop_sniffing)
        self.stop_button.pack(pady=10)
        self.stop_button.config(state=tk.DISABLED)

        self.sniffing = False
        self.thread = None

    def start_sniffing(self):
        self.sniffing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.thread = threading.Thread(target=self.sniffer)
        self.thread.start()

    def stop_sniffing(self):
        self.sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        if self.thread:
            self.thread.join()

    def sniffer(self):
        def packet_callback(packet):
            if IP in packet:
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst
                proto = packet[IP].proto

                protocol_name = self.get_protocol_name(proto)

                payload = bytes(packet[IP].payload)
                payload_hexdump = self.hexdump_format(payload)

                self.tree.insert('', tk.END, values=(ip_src, ip_dst, protocol_name, payload_hexdump))

        sniff(prn=packet_callback, store=0)

    def get_protocol_name(self, proto):
        proto_dict = {
            1: "ICMP",
            2: "IGMP",
            6: "TCP",
            17: "UDP",
            41: "IPv6",
            50: "ESP",
            51: "AH",
            89: "OSPF",
        }
        return proto_dict.get(proto, f"Other ({proto})")

    def hexdump_format(self, payload):
        return hexdump(payload, dump=True)

    def on_double_click(self, event):
        item = self.tree.selection()[0]
        payload = self.tree.item(item, "values")[3]

        popup = tk.Toplevel(self.master)
        popup.title("Full Payload")
        popup.geometry("600x400")

        text_area = scrolledtext.ScrolledText(popup, wrap=tk.WORD, width=70, height=20)
        text_area.pack(pady=10, padx=10)
        text_area.insert(tk.END, payload)

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSniffer(root)
    root.mainloop()
