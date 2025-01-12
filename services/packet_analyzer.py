from collections import defaultdict
import logging
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from queue import Empty
from rules.rule_manager import RuleManager
from rules.rule import Rule
import ipaddress
from services.config_service import ConfigService  # Importa ConfigService

class PacketAnalyzer:
    def __init__(self, packet_queue, rule_manager, config_dir="./configuration", home_net="192.168.145.0/24"):
        """
        Inizializza il PacketAnalyzer con una coda di pacchetti, RuleManager e configurazione.

        Args:
            packet_queue (queue.Queue): La coda da cui leggere i pacchetti.
            rule_manager (RuleManager): Oggetto RuleManager che gestisce i protocolli e le regole.
            config_dir (str): Directory per i file di configurazione JSON.
            home_net (str): Intervallo di IP per la rete locale (HOME_NET).
        """
        self.packet_queue = packet_queue
        self.rule_manager = rule_manager
        self.config_service = ConfigService(config_dir)  # Inizializza ConfigService
        self.home_net = ipaddress.IPv4Network(home_net)  # Converte l'IP in un oggetto di rete
        self.packet_history = defaultdict(list)  # Crea un dizionario per la cronologia dei pacchetti
        logging.debug(f"RuleManager type: {type(self.rule_manager)}")

    def analyze_packet(self, packet):
        try:
            # Verifica la presenza di un layer IP (IPv4 o IPv6)
            ip_layer = packet.getlayer(IP)
            if ip_layer is None:
                ip_layer = packet.getlayer(IPv6)

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
            protocol_name = self._map_protocol(protocol=protocol)

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

                # Verifica la direzione del pacchetto
                if not self.check_direction(rule, ip_layer.src, ip_layer.dst):
                    logging.debug(f"Direzione non corrispondente per la regola {rule} con il pacchetto {packet.summary()}")
                    continue  # Ignora pacchetto se la direzione non corrisponde alla regola
                else:
                    logging.debug(f"Direzione corrispondente per la regola {rule} con il pacchetto {packet.summary()}")

                # Procedi a verificare e applicare la regola se c'è una corrispondenza
                if Rule.match_rule(rule, packet, self.packet_history):
                    # Verifica se l'IP rientra in HOME_NET o EXTERNAL_NET
                    if self.is_home_net(ip_layer.src) and rule.src_ip != "any":
                        logging.debug(f"Pacchetto {packet.summary()} corrisponde a HOME_NET.")
                        self.apply_rule(rule, packet)
                    
                    elif self.is_external_net(ip_layer.src) and rule.src_ip != "any":
                        logging.debug(f"Pacchetto {packet.summary()} corrisponde a EXTERNAL_NET.")
                        self.apply_rule(rule, packet)

                    elif rule.src_ip == "any":
                        logging.debug(f"Regola applicata senza filtro per src_ip ('any') in {packet.summary()}")
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

    def _map_protocol(self, protocol):
        """
        Mappa i numeri di protocollo ai nomi utilizzati nel sistema.

        Args:
            protocol (int): Numero del protocollo.

        Returns:
            str: Nome del protocollo.
        """
        return self.config_service.get_protocol_name(protocol)

    def check_direction(self, rule, ip_src, ip_dst):
        """
        Verifica la direzione del pacchetto in base alla regola.
        
        Args:
            rule (Rule): La regola che stiamo valutando.
            ip_src (str): Indirizzo IP di origine del pacchetto.
            ip_dst (str): Indirizzo IP di destinazione del pacchetto.

        Returns:
            bool: True se la direzione della regola corrisponde al pacchetto, altrimenti False.
        """
        logging.debug(f"Verifica direzione per il pacchetto: {ip_src} -> {ip_dst}, direzione regola: {rule.direction}")

        if rule.direction == "in":
            if self.is_external_net(ip_src) and self.is_home_net(ip_dst):
                logging.debug(f"Direzione 'in' corrisponde: {ip_src} è esterno, {ip_dst} è interno.")
                return True
            else:
                logging.debug(f"Direzione 'in' non corrisponde: {ip_src} non è esterno o {ip_dst} non è interno.")
            
        elif rule.direction == "out":
            if self.is_home_net(ip_src) and self.is_external_net(ip_dst):
                logging.debug(f"Direzione 'out' corrisponde: {ip_src} è interno, {ip_dst} è esterno.")
                return True
            else:
                logging.debug(f"Direzione 'out' non corrisponde: {ip_src} non è interno o {ip_dst} non è esterno.")
            
        elif rule.direction == "both":
            if (self.is_home_net(ip_src) and self.is_external_net(ip_dst)) or \
            (self.is_external_net(ip_src) and self.is_home_net(ip_dst)):
                logging.debug(f"Direzione 'both' corrisponde: pacchetto da {ip_src} a {ip_dst}.")
                return True
            else:
                logging.debug(f"Direzione 'both' non corrisponde per {ip_src} -> {ip_dst}.")
        
        logging.debug(f"Direzione non valida per {rule.direction} con pacchetto {ip_src} -> {ip_dst}.")
        return False


    def is_home_net(self, ip):
        """
        Verifica se l'IP è parte della rete HOME_NET.
        """
        return self.config_service.is_in_home_net(ip)

    def is_external_net(self, ip):
        """
        Verifica se l'IP è parte della rete EXTERNAL_NET.
        """
        return self.config_service.is_in_external_net(ip)

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
