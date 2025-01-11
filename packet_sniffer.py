from scapy.all import sniff
import logging

class PacketSniffer:
    def __init__(self, interface, packet_queue):
        self.interface = interface
        self.packet_queue = packet_queue

    def start(self, stop_event):
        logging.debug(f"Avvio del packet sniffer su {self.interface}...")
        while not stop_event.is_set():  # Continua fino a quando stop_event non è impostato
            sniff(iface=self.interface, prn=self.enqueue_packet, store=False, timeout=1)
        logging.debug("Sniffer terminato.")

    def enqueue_packet(self, packet):
        if not self.packet_queue.full():
            self.packet_queue.put(packet)
        else:
            logging.warning("Coda piena, pacchetto scartato.")
