import json
import logging

class Protocols:
    def __init__(self, config_file="./protocols/config_protocols.json"):
        self.config_file = config_file
        self.protocols = []
        self.load_protocols()

    def load_protocols(self):
        try:
            with open(self.config_file, "r") as f:
                data = json.load(f)
                self.protocols = data.get("protocols", [])
                logging.info(f"Protocollo configurati: {self.protocols}")
        except Exception as e:
            logging.error(f"Errore nel caricamento dei protocolli: {e}")

    def is_supported(self, protocol):
        """Verifica se il protocollo è supportato"""
        return protocol in self.protocols
