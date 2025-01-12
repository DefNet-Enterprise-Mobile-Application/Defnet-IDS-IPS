import json
import logging


class Protocols:
    """
    Classe per la gestione dei protocolli di rete supportati.

    Questa classe carica i protocolli da un file di configurazione JSON e 
    fornisce metodi per verificare se un determinato protocollo è supportato.
    La configurazione dei protocolli viene letta dal file specificato al momento 
    dell'inizializzazione, e i protocolli supportati sono memorizzati in una lista.

    Attributi:
    -----------
    config_file (str): Il percorso del file JSON che contiene la configurazione dei protocolli.
                        Il valore predefinito è "./protocols/config_protocols.json".
    protocols (list): Lista dei protocolli supportati, caricati dal file di configurazione.

    Metodi:
    --------
    load_protocols():
        Carica i protocolli dal file di configurazione.
        
    is_supported(protocol):
        Verifica se un dato protocollo è supportato.
    """

    def __init__(self, config_file="./protocols/config_protocols.json"):
        """
        Inizializza la classe Protocols.

        Carica i protocolli da un file JSON e li memorizza in una lista.

        Argomenti:
            config_file (str): Percorso del file JSON contenente la configurazione dei protocolli.
                               Il valore predefinito è "./protocols/config_protocols.json".
        """
        self.config_file = config_file
        self.protocols = []
        self.load_protocols()

    def load_protocols(self):
        """
        Carica i protocolli dal file di configurazione JSON.

        Questo metodo legge il file JSON specificato in `config_file` e popola la lista `protocols` 
        con i protocolli configurati. Se il file non può essere letto o il formato è errato, 
        viene registrato un errore nel log.

        Eccezioni:
            Se si verifica un errore durante la lettura del file o la parsificazione del JSON, 
            viene registrato un messaggio di errore.
        """
        try:
            with open(self.config_file, "r") as f:
                data = json.load(f)
                self.protocols = data.get("protocols", [])
                logging.info(f"Protocollo configurati: {self.protocols}")
        except Exception as e:
            logging.error(f"Errore nel caricamento dei protocolli: {e}")

    def is_supported(self, protocol):
        """
        Verifica se un protocollo è supportato.

        Controlla se il protocollo passato come argomento è presente nella lista dei protocolli 
        supportati, che è stata caricata dal file di configurazione.

        Argomenti:
            protocol (str): Il nome del protocollo da verificare.

        Restituisce:
            bool: True se il protocollo è supportato, False altrimenti.
        """
        return protocol in self.protocols
