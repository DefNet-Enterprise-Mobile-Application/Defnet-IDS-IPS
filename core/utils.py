import argparse
import logging
import os

def setup_logging(log_file="/tmp/openwrt-ids-ips.log"):
    """
    Configura la registrazione dei log per l'applicazione.

    Questo metodo imposta il livello di log e il formato del messaggio di log, 
    e specifica il file in cui i log verranno registrati. Il livello di log 
    è impostato su DEBUG per consentire la registrazione di informazioni dettagliate 
    durante l'esecuzione dell'applicazione. I log verranno scritti nel file 
    specificato nel parametro `log_file`.

    Argomenti:
        log_file (str): Il percorso completo del file di log dove i messaggi 
                        di log saranno scritti. Il valore predefinito è 
                        "/tmp/openwrt-ids-ips.log".

    Comportamento:
        - Imposta il livello di log su DEBUG, il che significa che verranno registrati 
          messaggi di livello DEBUG, INFO, WARNING, ERROR e CRITICAL.
        - Usa il formato `'%(asctime)s - %(levelname)s - %(message)s'` per i messaggi di log, 
          che includerà la data, il livello del log e il messaggio stesso.
        - Aggiunge un gestore di log di tipo `FileHandler` che scrive nel file specificato.

    Esempio di utilizzo:
        setup_logging("/path/to/logfile.log")
        logging.debug("Questo è un messaggio di debug.")
        logging.info("Informazioni generali.")
        logging.warning("Un avviso.")
        logging.error("Un errore.")
    """
    logging.basicConfig(
        level=logging.DEBUG,  # Aumentato a DEBUG per vedere più dettagli
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),  # Scrive solo nel file di log
        ]
    )



def parse_arguments():
    """
    Analizza gli argomenti da riga di comando.

    Restituisce:
        Namespace con gli argomenti forniti dalla riga di comando.
    """
    parser = argparse.ArgumentParser(description="Sniffer di rete con Scapy")
    parser.add_argument(
        "-i", "--interface", 
        required=True, 
        help="Interfaccia di rete da analizzare (es. eth0, wlan0, etc.)"
    )
    parser.add_argument(
        "-c", "--config", 
        required=False, 
        default="./rules/config_rules.json", 
        help="Percorso al file di configurazione delle regole (default: config_rules.json)"
    )
    parser.add_argument(
        "--home-net", 
        required=False, 
        default="192.168.1.0/24", 
        help="Indirizzo di rete HOME_NET (es. 192.168.1.0/24, 10.0.0.0/8, singolo indirizzo IP)."
    )
    parser.add_argument(
        "command", 
        choices=["start", "stop"], 
        help="Comando per avviare o fermare il servizio"
    )
    return parser.parse_args()


def clear_log_file():
    """
    Gestisce la creazione e la pulizia del file di log.
    
    Il file di log è situato in '/tmp/openwrt-ids-ips.log'. Se il file esiste, viene svuotato, 
    altrimenti viene creato un file vuoto.
    """
    log_file = "/tmp/openwrt-ids-ips.log"
    try:
        # Se il file esiste, svuotalo
        if os.path.exists(log_file):
            open(log_file, 'w').close()  # Svuota il file
            logging.info(f"File di log {log_file} svuotato.")
        else:
            # Se il file non esiste, crealo
            with open(log_file, 'w') as f:
                f.write("")  # Crea un file vuoto
            logging.info(f"File di log {log_file} creato.")
    except Exception as e:
        logging.error(f"Errore durante la gestione del file di log: {e}")



# Valore di default per il file dei protocolli
DEFAULT_PROTOCOL_CONFIG = "./configuration/config_protocols.json"

DEFAULT_SETTINGS_CONFIG = "./configuration/config_settings.json"

DEFAULT_RULES_CONFIG = "./rules/config_rules.json"


URL_MICROSERVICE="http://"
IP_ADDRESS_MICROSERVICE="10.71.71.144"
PORT_MICROSERVICE="8000"

DEFUALT_NOTIFICATION_ALERT_CONFIG = f"{URL_MICROSERVICE}{IP_ADDRESS_MICROSERVICE}:{PORT_MICROSERVICE}/notify-alert"