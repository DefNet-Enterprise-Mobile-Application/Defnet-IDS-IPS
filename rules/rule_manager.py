import json
import logging
from radixTree.radix_tree import RadixTree

class RuleManager:
    def __init__(self, protocol_config_file):
        """
        Inizializza il RuleManager e carica i protocolli da un file di configurazione.
        :param protocol_config_file: Percorso al file di configurazione dei protocolli.
        """
        self.protocol_rules = {}  # Dizionario che conterrà un RadixTree per ogni protocollo
        self.load_protocols(protocol_config_file)

    def load_protocols(self, protocol_config_file):
        logging.info("Sto per caricare i protocolli : ")
        try:
            with open(protocol_config_file, "r") as f:
                data = json.load(f)
                protocols = data.get("protocols", [])  # Lista di protocolli nel file JSON
                logging.debug(f"Protocollo trovati nel file di configurazione: {protocols}")

                for protocol in protocols:
                    self.protocol_rules[protocol] = RadixTree()
                    logging.info(f"Protocollo {protocol} aggiunto con RadixTree.")

        except FileNotFoundError:
            logging.error(f"File di configurazione {protocol_config_file} non trovato.")
        except json.JSONDecodeError as e:
            logging.error(f"Errore nella lettura del file JSON: {e}")
        except Exception as e:
            logging.error(f"Errore imprevisto durante il caricamento dei protocolli: {e}")


    def add_rule(self, protocol, ip_prefix, rule):
        """
        Aggiunge una regola al RadixTree del protocollo specificato se non esiste già (basato su ID regola).
        :param protocol: Nome del protocollo (es. TCP, UDP).
        :param ip_prefix: Prefisso IP associato alla regola.
        :param rule: Oggetto regola.
        """
        if protocol in self.protocol_rules:
            # Cerca esistente nella Radix Tree del protocollo per verificare duplicati
            existing_rule = self.protocol_rules[protocol].search(ip_prefix)
            # Se esiste almeno una regola con lo stesso prefisso, procedi ad aggiungere
            if existing_rule:
                logging.debug(f"Regola già presente per {protocol} e IP {ip_prefix}. Verifica ID regola.")
            # Aggiungi la regola usando il metodo insert
            self.protocol_rules[protocol].insert(ip_prefix, rule)
            logging.debug(f"Regola aggiunta al protocollo {protocol}: {rule}")
        else:
            logging.warning(f"Protocollo {protocol} non supportato.")

    def get_matching_rules(self, protocol, ip):
        # Verifica se il protocollo è presente nelle regole
        if protocol in self.protocol_rules:
            # Verifica se la struttura è un'istanza di RadixTree
            if isinstance(self.protocol_rules[protocol], RadixTree):
                # Cerca le regole utilizzando il metodo search
                rules = self.protocol_rules[protocol].search(ip)
                if rules is None:
                    logging.debug(f"Nessuna regola trovata per protocollo {protocol} e IP {ip}.")
                else:
                    logging.debug(f"Regole trovate per protocollo {protocol} e IP {ip}: {rules}")
                return rules or []  # Restituisce una lista vuota se non ci sono regole
            else:
                logging.error(f"La struttura per il protocollo {protocol} non è un'istanza di RadixTree.")
                return []
        else:
            logging.warning(f"Protocollo {protocol} non supportato.")
            return []




