import logging
from queue import Empty

class PacketAnalyzer:
    def __init__(self, packet_queue):
        self.packet_queue = packet_queue

    def analyze_packet(self, packet):
        if packet.haslayer("IP"):
            ip_src = packet["IP"].src
            ip_dst = packet["IP"].dst
            logging.debug(f"Analisi pacchetto: da {ip_src} a {ip_dst}")
            logging.info(f"Pacchetto da {ip_src} a {ip_dst}")
            # Aggiungi logica personalizzata qui

    def start(self, stop_event):
        logging.info("Modulo di analisi avviato...")
        while not stop_event.is_set() or not self.packet_queue.empty():  # Termina solo quando il servizio è fermo e la coda è vuota
            try:
                # Prova a prelevare un pacchetto dalla coda
                packet = self.packet_queue.get(timeout=1)  # timeout per non bloccare troppo
                self.analyze_packet(packet)
            except Empty:
                logging.debug("La coda è vuota, nessun pacchetto da elaborare.")
                continue  # Continua a cercare pacchetti da elaborare
            except Exception as e:
                logging.error(f"Errore durante l'analisi del pacchetto: {e}")
                continue
        logging.info("Analyzer terminato.")
