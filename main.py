import argparse
import logging
import os
from service_manager import ServiceManager

def parse_arguments():
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
        "command", 
        choices=["start", "stop"], 
        help="Comando per avviare o fermare il servizio"
    )
    return parser.parse_args()

def clear_log_file():
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

if __name__ == "__main__":
    args = parse_arguments()
    interface = args.interface
    config_file = args.config

    # Imposta il logging
    logging.basicConfig(level=logging.INFO)

    # Svuota o crea il file di log
    clear_log_file()

    # Inizializzazione del service manager con la configurazione
    service_manager = ServiceManager(interface, config_file)

    if args.command == "start":
        service_manager.start()
    elif args.command == "stop":
        # Logica per fermare il servizio, se necessario
        logging.info("Comando stop ricevuto.")

