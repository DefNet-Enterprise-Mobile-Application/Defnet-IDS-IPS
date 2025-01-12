from scapy.layers.inet import IP, TCP, UDP  # Aggiungi qui l'importazione del layer IP
from scapy.layers.inet6 import IPv6  # Aggiungi qui l'importazione per IPv6

import logging
from queue import Empty
from rule_manager.rule_manager import RuleManager

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
        logging.debug(f"RuleManager type: {type(self.rule_manager)}")

    def analyze_packet(self, packet):
        try:
            # Verifica la presenza di un layer IP (IPv4 o IPv6)
            ip_layer = packet.getlayer(IP)  # Modifica qui per usare IP dal modulo inet
            if ip_layer is None:
                ip_layer = packet.getlayer(IPv6)  # Modifica per usare IPv6 dal modulo inet6

            if ip_layer is None:
                logging.warning(f"Pacchetto senza layer IP o IPv6: {packet.summary()}")
                return  # Ignora pacchetto se non ha layer IP o IPv6

            # Log dettagliato per il protocollo
            if isinstance(ip_layer, IP):
                protocol = ip_layer.proto  # protocollo per IPv4
            elif isinstance(ip_layer, IPv6):
                protocol = ip_layer.nh  # protocollo per IPv6

            logging.debug(f"Protocollo del pacchetto: {protocol}")

            # Mappatura numeri di protocollo ai nomi
            if protocol == 1:
                protocol_name = "ICMP"
            elif protocol == 6:
                protocol_name = "TCP"
            elif protocol == 17:
                protocol_name = "UDP"
            elif protocol == 58:
                protocol_name = "ICMPv6"
            else:
                protocol_name = f"Unknown protocol {protocol}"

            logging.debug(f"Protocollo del pacchetto identificato: {protocol_name}")

            # Cerca le regole per il protocollo
            if isinstance(self.rule_manager, RuleManager):
                rules = self.rule_manager.get_matching_rules(protocol_name, ip_layer.src)
            else:
                logging.error("Il RuleManager non è stato inizializzato correttamente.")
                return

            if not rules:
                logging.debug(f"Nessuna regola trovata per il pacchetto con protocollo {protocol_name} e IP {ip_layer.src}.")
                return

            # Applica le regole trovate
            for rule in rules:
                logging.debug(f"Controllando la regola: {rule} per pacchetto: {packet.summary()}")
                if rule.matches(packet):
                    self.apply_rule(rule, packet)
                else:
                    logging.debug(f"Nessun match per la regola {rule} con il pacchetto {packet.summary()}")

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
