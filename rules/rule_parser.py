import json
import logging
from rules.rule import Rule

class RuleParser:
    def __init__(self, config_file, rule_manager):
        """
        Inizializza il parser con il percorso del file di configurazione e il RuleManager.

        Args:
            config_file (str): Il percorso al file JSON che contiene le regole.
            rule_manager (RuleManager): Oggetto RuleManager per aggiungere le regole ai RadixTree.
        """
        self.config_file = config_file
        self.rule_manager = rule_manager
        self.rules = []

    def parse(self):
        """
        Esegue il parsing del file di configurazione JSON e carica le regole nel RuleManager.
        """
        try:
            with open(self.config_file, "r") as f:
                data = json.load(f)

                for rule_data in data["rules"]:
                    # Estrai e assegna valori di default se assenti
                    dst_ip = rule_data.get("dst_ip", "any")
                    src_ip = rule_data.get("src_ip", "any")
                    src_port = rule_data.get("src_port", "any")
                    dst_port = rule_data.get("dst_port", "any")
                    direction = rule_data.get("direction", "both")  # Aggiungi la gestione del parametro direction

                    # Crea un oggetto Rule con il parametro direction
                    rule = Rule(
                        rule_data["rule_id"],
                        rule_data["protocol"],
                        src_ip,
                        dst_ip,
                        src_port,
                        dst_port,
                        rule_data.get("action"),
                        rule_data.get("description"),
                        direction  # Passa la direzione alla regola
                    )

                    # Aggiungi la regola al RuleManager
                    self.rule_manager.add_rule(rule.protocol, src_ip, rule)
                    logging.info(f"Regola caricata: {rule}")
        except Exception as e:
            logging.error(f"Errore nel parsing del file di configurazione: {e}")
