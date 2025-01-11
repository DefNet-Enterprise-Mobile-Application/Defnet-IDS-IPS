import logging
from queue import Empty
from rule import Rule

class PacketAnalyzer:
    def __init__(self, packet_queue, rule_manager):
        """
        Inizializza il PacketAnalyzer con una coda di pacchetti e un RuleManager.

        Args:
            packet_queue (queue.Queue): La coda da cui leggere i pacchetti.
            rule_manager (RuleManager): Oggetto RuleManager che gestisce i protocolli e le regole.
        """
        self.packet_queue = packet_queue
        self.rule_manager = rule_manager

    def analyze_packet(self, packet):
        """
        Analizza un pacchetto in base alle regole caricate.

        Args:
            packet: Un oggetto rappresentante il pacchetto da analizzare (tipicamente fornito da Scapy).
        """
        try:
            # Verifica la presenza del layer IP nel pacchetto
            ip_layer = packet.getlayer("IP")
            if ip_layer is None:
                logging.warning(f"Pacchetto senza layer IP: {packet.summary()}")
                return  # Ignora il pacchetto se non ha un layer IP

            # Otteniamo il protocollo del pacchetto (ad esempio "TCP")
            protocol = ip_layer.proto

            # Cerchiamo le regole per il protocollo
            rules = self.rule_manager.get_matching_rules(protocol, ip_layer.src)
        
            if not rules:
                logging.debug(f"Nessuna regola trovata per il pacchetto con protocollo {protocol} e IP {ip_layer.src}.")
                return  # Nessuna regola trovata, ignora il pacchetto

            for rule in rules:
                if rule.matches(packet):
                    self.apply_rule(rule, packet)

        except Exception as e:
            logging.error(f"Errore durante l'analisi del pacchetto: {e}")

    def apply_rule(self, rule, packet):
        """
        Applica l'azione definita da una regola al pacchetto corrispondente.

        Args:
            rule (Rule): La regola che è stata corrisposta al pacchetto.
            packet: Il pacchetto che ha corrisposto alla regola.
        """
        if rule.action == "alert":
            logging.warning(f"Allerta: {rule.description} per pacchetto {packet.summary()}")
        elif rule.action == "block":
            logging.info(f"Bloccato: {rule.description} per pacchetto {packet.summary()}")
        else:
            logging.debug(f"Regola applicata senza azione: {rule.description}")

    def start(self, stop_event):
        """
        Avvia il modulo di analisi dei pacchetti.

        Args:
            stop_event (threading.Event): Un evento che segnala quando terminare il processo di analisi.
        """
        logging.info("Modulo di analisi avviato...")
        while not stop_event.is_set() or not self.packet_queue.empty():
            try:
                packet = self.packet_queue.get(timeout=1)
                self.analyze_packet(packet)
            except Empty:
                logging.debug("La coda è vuota, nessun pacchetto da elaborare.")
                continue
            except Exception as e:
                logging.error(f"Errore durante l'analisi del pacchetto: {e}")
                continue
        logging.info("Analyzer terminato.")
