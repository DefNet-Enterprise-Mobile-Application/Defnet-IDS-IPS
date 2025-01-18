from collections import defaultdict
import logging
import os
import time
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from queue import Empty
from rules.rule_manager import RuleManager
from rules.rule import Rule
import ipaddress
from services.config_service import ConfigService
from services.notification_manager import NotificationManager  # Importa ConfigService
from core.utils import DEFUALT_NOTIFICATION_ALERT_CONFIG
import subprocess


class PacketAnalyzer:
    def __init__(self, packet_queue, rule_manager, config_dir="./configuration",home_net="192.168.145.0/24", notification_manager=None ):
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
        
        self.blacklist = set()  # Inizializza la blacklist

        self.notification_manager = notification_manager # Inizializza un Thread che permette di notificare il mio webSocket


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
            

            logging.debug(f"Voglio visualizzare tutte le regole che ci sono : {rules}")

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
                        self.apply_rule(rule, packet, self.sanitize_ip(ip_layer.src))
                    
                    elif self.is_external_net(ip_layer.src) and rule.src_ip != "any":
                        logging.debug(f"Pacchetto {packet.summary()} corrisponde a EXTERNAL_NET.")
                        self.apply_rule(rule, packet, self.sanitize_ip(ip_layer.src))

                    elif rule.src_ip == "any":
                        logging.debug(f"Regola applicata senza filtro per src_ip ('any') in {packet.summary()}")
                        self.apply_rule(rule, packet, self.sanitize_ip(ip_layer.src))
                
                else:
                    logging.debug(f"Nessun match per la regola {rule} con il pacchetto {packet.summary()}")

        except Exception as e:
            logging.error(f"Errore durante l'analisi del pacchetto: {e}")


    def apply_rule(self, rule, packet, ip_layer_src):
        """
        Applica l'azione definita da una regola al pacchetto corrispondente.

        Args:
            rule (Rule): La regola che è stata corrisposta al pacchetto.
            packet: Il pacchetto che ha corrisposto alla regola.
            ip_layer_src (str): Indirizzo IP sorgente del pacchetto.
        """
        # Estrai informazioni di base dal pacchetto
        packet_summary = packet.summary()
        ip_layer_dst = getattr(packet, "dst", "unknown")

        # Notifica basata sull'azione della regola
        if rule.action == "alert":
            logging.warning(f"Allerta: {rule.description} per pacchetto {packet_summary}")

            # Creazione della notifica
            notification = {
                "rule_id": rule.rule_id if hasattr(rule, "rule_id") else "unknown",  # Usa 'unknown' se manca l'ID
                "type": "alert", # alert 
                "description": rule.description,
                "packet": packet_summary,
                "timestamp": time.time(),
                "src_ip": ip_layer_src,
                "dst_ip": ip_layer_dst,
            }

            logging.info(f"Generato alert: {notification}")

            # Aggiungi l'evento al NotificationManager
            if self.notification_manager:
                self.notification_manager.add_event(notification)
            return

        elif rule.action == "block":
            logging.info(f"Bloccato: {rule.description} per pacchetto {packet_summary}")
            self.add_to_blacklist(ip_layer_src)

             # Creazione della notifica
            notification = {
                "rule_id": rule.rule_id if hasattr(rule, "rule_id") else "unknown",  # Usa 'unknown' se manca l'ID
                "type": "block", # warning 
                "description": rule.description + "(Bloccato)",
                "packet": packet_summary,
                "timestamp": time.time(),
                "src_ip": ip_layer_src,
                "dst_ip": ip_layer_dst,
            }
            # Aggiungi l'evento al NotificationManager
            if self.notification_manager:
                self.notification_manager.add_event(notification)
            return

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

    def add_to_blacklist(self, ip):
        """
        Aggiunge un indirizzo IP alla blacklist e blocca il traffico tramite iptables.
        Se l'IP è già presente, lo sostituisce rimuovendo le vecchie regole.
        """
        if ip in self.blacklist:
            logging.info(f"{ip} già nella blacklist. Sostituendo regole esistenti.")
            self.remove_ip_from_iptables(ip)

        # Aggiungi l'IP alla blacklist e crea le regole
        self.blacklist.add(ip)
        logging.info(f"Aggiunto {ip} alla blacklist. Blocco attivo.")
        os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
        os.system(f"sudo iptables -A OUTPUT -d {ip} -j DROP")

    def remove_ip_from_iptables(self, ip):
        """
        Rimuove le regole di iptables associate a un indirizzo IP specifico.
        """
        try:
            subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            subprocess.run(["sudo", "iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"], check=True)
            logging.info(f"Regole di iptables rimosse per {ip}.")
        except subprocess.CalledProcessError as e:
            logging.error(f"Errore nella rimozione delle regole di iptables per {ip}: {e.stderr}")


    def clear_blacklist(self):
        """
        Rimuove tutti gli IP dalla blacklist e pulisce le regole di iptables.
        """
        for ip in list(self.blacklist):  # Usa una copia della lista per evitare modifiche durante l'iterazione
            logging.info(f"Rimuovendo {ip} dalla blacklist.")
            try:
                # Rimuovi l'IP dalla regola INPUT
                subprocess.run(
                    ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                    check=True, capture_output=True, text=True
                )

                # Rimuovi l'IP dalla regola OUTPUT
                subprocess.run(
                    ["sudo", "iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"],
                    check=True, capture_output=True, text=True
                )

                logging.info(f"Rimosso {ip} con successo.")

            except subprocess.CalledProcessError as e:
                logging.error(f"Errore nella rimozione dell'IP {ip}: {e.stderr}")
                continue

            # Rimuovi l'IP dalla blacklist solo se le regole sono state eliminate
            self.blacklist.remove(ip)

        # Una volta rimossa la blacklist, pulisce completamente
        self.blacklist.clear()
        logging.info("Blacklist pulita.")




    def set_notification_manager(self, notification_manager):
        """
        Collega il NotificationManager al PacketAnalyzer.

        Args:
            notification_manager (NotificationManager): Istanza del NotificationManager.
        """
        self.notification_manager = notification_manager

    def sanitize_ip(self, ip):
        """
        Rimuove la porta da un indirizzo IP (se presente) e restituisce solo l'indirizzo.
        
        Args:
            ip (str): L'indirizzo IP con la porta, nel formato 'indirizzo:porta'.
        
        Returns:
            str: L'indirizzo IP senza la porta.
        """
        return ip.split(":")[0] if ":" in ip else ip