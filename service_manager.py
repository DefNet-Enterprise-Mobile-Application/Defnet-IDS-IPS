import signal
import logging
from threading import Thread
from packet_sniffer import PacketSniffer
from packet_analyzer import PacketAnalyzer
from queue import Queue
from utils import setup_logging
from threading import Event

class ServiceManager:
    def __init__(self, interface):
        setup_logging()  # Imposta il logging
        self.interface = interface
        self.packet_queue = Queue(maxsize=100)
        self.sniffer = PacketSniffer(interface, self.packet_queue)
        self.analyzer = PacketAnalyzer(self.packet_queue)
        self.stop_event = Event()  # Evento per fermare i thread

    def handle_termination_signal(self, signal, frame):
        logging.info("Ricevuto segnale di terminazione. Arresto del servizio...")
        self.stop_event.set()  # Impostiamo l'evento per fermare i thread

    def start(self):
        logging.debug("Avvio del servizio...")

        # Gestione dei segnali di terminazione
        signal.signal(signal.SIGTERM, self.handle_termination_signal)

        # Avvio dei thread di sniffer e analisi
        sniffer_thread = Thread(target=self.sniffer.start, args=(self.stop_event,))
        analyzer_thread = Thread(target=self.analyzer.start, args=(self.stop_event,))

        sniffer_thread.start()
        analyzer_thread.start()

        # Unisci i thread (attendiamo che finiscano)
        sniffer_thread.join()
        analyzer_thread.join()

