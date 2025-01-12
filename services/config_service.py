import json
import ipaddress
import logging
import os


class ConfigService:

    def __init__(self, config_dir="./configuration"):
        """
        Inizializza il ConfigService e carica le configurazioni dalla directory specificata.

        :param config_dir: Directory contenente i file JSON di configurazione.
        """
        self.config_dir = config_dir
        self.protocols = []
        self.settings = {}
        self._load_all_configs()

    def _load_all_configs(self):
        """
        Carica tutti i file di configurazione richiesti.
        """
        self.protocols = self._load_protocols()
        self.settings = self._load_settings()
        logging.info("Tutte le configurazioni sono state caricate con successo.")

    def _load_protocols(self):
        """
        Carica la configurazione dei protocolli dal file config_protocols.json.

        :return: Lista dei protocolli configurati.
        """
        file_path = os.path.join(self.config_dir, "config_protocols.json")
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                logging.info(f"Protocolli caricati da {file_path}: {data}")
                return data.get("protocols", [])
        except FileNotFoundError:
            logging.error(f"File di configurazione {file_path} non trovato.")
        except json.JSONDecodeError as e:
            logging.error(f"Errore nella lettura del file JSON {file_path}: {e}")
        except Exception as e:
            logging.error(f"Errore imprevisto durante il caricamento dei protocolli: {e}")
        return []

    def _load_settings(self):
        """
        Carica la configurazione dei settings dal file config_settings.json.

        :return: Dizionario dei settings configurati.
        """
        file_path = os.path.join(self.config_dir, "config_settings.json")
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                logging.info(f"Settings caricati da {file_path}: {data}")
                return data.get("settings", {})
        except FileNotFoundError:
            logging.error(f"File di configurazione {file_path} non trovato.")
        except json.JSONDecodeError as e:
            logging.error(f"Errore nella lettura del file JSON {file_path}: {e}")
        except Exception as e:
            logging.error(f"Errore imprevisto durante il caricamento dei settings: {e}")
        return {}

    def is_in_home_net(self, ip):
        """
        Verifica se un IP appartiene alla rete HOME_NET.

        :param ip: Indirizzo IP da verificare.
        :return: True se l'IP è in HOME_NET, False altrimenti.
        """
        home_net = self.settings.get("HOME_NET")
        if not home_net:
            logging.warning("HOME_NET non configurata.")
            return False

        try:
            network = ipaddress.ip_network(home_net, strict=False)
            result = ipaddress.ip_address(ip) in network
            logging.debug(f"Verifica HOME_NET: {ip} in {home_net} -> {result}")
            return result
        except ValueError as e:
            logging.error(f"Errore nel parsing di HOME_NET o IP: {e}")
            return False

    def is_in_external_net(self, ip):
        """
        Verifica se un IP appartiene a EXTERNAL_NET, supportando la negazione.

        :param ip: Indirizzo IP da verificare.
        :return: True se l'IP appartiene a EXTERNAL_NET, False altrimenti.
        """
        external_net = self.settings.get("EXTERNAL_NET")
        if not external_net:
            logging.warning("EXTERNAL_NET non configurata.")
            return False

        result = ConfigService._check_external_net(ip, external_net)
        logging.debug(f"Verifica EXTERNAL_NET: {ip} in {external_net} -> {result}")
        return result


    @staticmethod
    def _check_external_net(ip, external_net_config):
        """
        Verifica se un indirizzo IP appartiene a EXTERNAL_NET con supporto per la negazione.

        :param ip: Indirizzo IP da verificare.
        :param external_net_config: Configurazione EXTERNAL_NET.
        :return: True se l'IP appartiene a EXTERNAL_NET, False altrimenti.
        """
        if not external_net_config:
            logging.warning("EXTERNAL_NET non configurata.")
            return False

        try:
            ip_obj = ipaddress.ip_address(ip)
            rules = [rule.strip() for rule in external_net_config.split(",")]
            excluded = []

            for rule in rules:
                if rule.startswith("!"):
                    excluded.append(ipaddress.ip_network(rule[1:].strip(), strict=False))
                else:
                    network = ipaddress.ip_network(rule.strip(), strict=False)
                    if ip_obj in network:
                        return True

            for excluded_network in excluded:
                if ip_obj in excluded_network:
                    return False

            return False

        except ValueError as e:
            logging.error(f"Errore nel parsing di EXTERNAL_NET o IP: {e}")
            return False

    def get_protocol_name(self, protocol):
        """
        Restituisce il nome del protocollo dato il numero.

        :param protocol: Numero del protocollo.
        :return: Nome del protocollo come stringa.
        """
        protocol_names = {
            1: "ICMP",
            6: "TCP",
            17: "UDP",
            58: "ICMPv6",
            2: "IGMP",
            3: "GGP",
            4: "IP",
            50: "ESP (Encapsulating Security Payload)",
            51: "AH (Authentication Header)",
            88: "EIGRP (Enhanced Interior Gateway Routing Protocol)",
            89: "OSPF (Open Shortest Path First)",
            132: "SCTP (Stream Control Transmission Protocol)"
        }

        return protocol_names.get(protocol, f"Unknown protocol {protocol}")
