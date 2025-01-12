import signal
import logging
from threading import Thread, Event
from queue import Queue
from services.packet_sniffer import PacketSniffer
from services.packet_analyzer import PacketAnalyzer
from rules.rule_manager import RuleManager
from rules.rule_parser import RuleParser
from core.utils import setup_logging

class ServiceManager:
    """
    Gestisce il ciclo di vita del servizio di sniffing e analisi dei pacchetti, 
    includendo il caricamento delle regole di analisi e la gestione dei segnali di terminazione.

    Attributes:
        interface (str): Interfaccia di rete su cui operare (es. eth0, wlan0).
        config_file (str): Percorso al file di configurazione delle regole.
        packet_queue (Queue): Coda condivisa per i pacchetti catturati.
        sniffer (PacketSniffer): Componente per lo sniffing dei pacchetti.
        analyzer (PacketAnalyzer): Componente per l'analisi dei pacchetti.
        stop_event (Event): Evento per coordinare l'arresto dei thread.
    """
    def __init__(self, interface, config_file="./rules/config_rules.json", protocol_config="./protocols/config_protocols.json"):
        """
        Inizializza il ServiceManager con l'interfaccia di rete e il file di configurazione delle regole.

        Args:
            interface (str): Interfaccia di rete su cui operare (es. eth0, wlan0).
            config_file (str): Percorso al file di configurazione delle regole (default: "config_rules.json").
        """
        setup_logging()  # Imposta il logging
        self.interface = interface
        self.config_file = config_file
        self.packet_queue = Queue(maxsize=100)
        self.stop_event = Event()  # Evento per fermare i thread


        # Inizializza RuleManager
        rule_manager = RuleManager(protocol_config)  # Crea un'istanza di RuleManager

        # Caricamento delle regole
        rule_parser = RuleParser(config_file, rule_manager)
        rule_parser.parse()
        self.rules = rule_parser.rules

        # Inizializza i componenti sniffer e analyzer con le regole caricate
        self.sniffer = PacketSniffer(interface, self.packet_queue)
        self.analyzer = PacketAnalyzer(self.packet_queue, rule_manager)

    def handle_termination_signal(self, signal, frame):
        """
        Gestisce i segnali di terminazione (es. SIGTERM) per arrestare il servizio in modo sicuro.

        Args:
            signal (int): Segnale ricevuto.
            frame (FrameType): Frame corrente (non utilizzato).
        """
        logging.info("Ricevuto segnale di terminazione. Arresto del servizio...")
        self.stop_event.set()  # Imposta l'evento per fermare i thread

    def start(self):
        """
        Avvia il servizio di sniffing e analisi dei pacchetti.

        Questa funzione avvia due thread principali:
        1. Thread per lo sniffing dei pacchetti (PacketSniffer).
        2. Thread per l'analisi dei pacchetti (PacketAnalyzer).

        Inoltre, si occupa della gestione dei segnali di terminazione.
        """
        logging.info(f"Avvio del servizio sull'interfaccia {self.interface} con il file di configurazione {self.config_file}")

        # Gestione dei segnali di terminazione
        signal.signal(signal.SIGTERM, self.handle_termination_signal)
        signal.signal(signal.SIGINT, self.handle_termination_signal)

        # Avvio dei thread di sniffer e analisi
        sniffer_thread = Thread(target=self.sniffer.start, args=(self.stop_event,))
        analyzer_thread = Thread(target=self.analyzer.start, args=(self.stop_event,))

        sniffer_thread.start()
        analyzer_thread.start()

        logging.info("Servizio avviato. Premere Ctrl+C per terminare.")

        # Unisci i thread (attendiamo che finiscano)
        sniffer_thread.join()
        analyzer_thread.join()

        logging.info("Servizio terminato.")

    def stop(self):
        """
        Arresta il servizio impostando l'evento di stop per tutti i componenti.
        """
        logging.info("Arresto del servizio...")
        self.stop_event.set()