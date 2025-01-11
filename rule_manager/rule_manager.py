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

    def load_protocols(self, config_file):
        """
        Carica i protocolli dal file JSON e inizializza un RadixTree per ciascuno.
        :param config_file: Percorso del file JSON di configurazione.
        """
        try:
            # Leggiamo il file di configurazione dei protocolli
            with open(config_file, "r") as f:
                data = json.load(f)
                protocols = data.get("protocols", [])  # Lista di protocolli nel file JSON

                # Per ogni protocollo, inizializziamo un RadixTree e lo memorizziamo nel dizionario
                for protocol in protocols:
                    self.protocol_rules[protocol] = RadixTree()
                    logging.info(f"Protocollo {protocol} aggiunto con RadixTree.")

        except FileNotFoundError:
            logging.error(f"File di configurazione {config_file} non trovato.")
        except json.JSONDecodeError as e:
            logging.error(f"Errore nella lettura del file JSON: {e}")
        except Exception as e:
            logging.error(f"Errore imprevisto durante il caricamento dei protocolli: {e}")

    def add_rule(self, protocol, ip_prefix, rule):
        """
        Aggiunge una regola al RadixTree del protocollo specificato.
        :param protocol: Nome del protocollo (es. TCP, UDP).
        :param ip_prefix: Prefisso IP associato alla regola.
        :param rule: Oggetto regola.
        """
        if protocol in self.protocol_rules:
            self.protocol_rules[protocol].insert(ip_prefix, rule)
            logging.info(f"Regola aggiunta al protocollo {protocol}: {rule}")
        else:
            logging.warning(f"Protocollo {protocol} non supportato.")

    def get_matching_rules(self, protocol, ip):
        """
        Restituisce le regole applicabili per il protocollo e l'indirizzo IP specificati.
        :param protocol: Nome del protocollo (es. TCP, UDP).
        :param ip: Indirizzo IP per cui cercare le regole.
        :return: Lista di regole corrispondenti.
        """
        if protocol in self.protocol_rules:
            rules = self.protocol_rules[protocol].search(ip)
            if rules is None:
                logging.debug(f"Nessuna regola trovata per protocollo {protocol} e IP {ip}.")
            return rules or []  # Restituisce una lista vuota se non ci sono regole
        return []

