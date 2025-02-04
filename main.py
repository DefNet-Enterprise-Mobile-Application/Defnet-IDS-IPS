"""
Sniffer di rete e gestione dei servizi con Scapy e ServiceManager

Questo script consente di avviare o fermare un servizio che utilizza Scapy per il monitoraggio e l'analisi del traffico di rete sulla macchina. Può essere configurato con un file di configurazione delle regole e permette di operare su un'interfaccia di rete specifica. Viene utilizzato anche un file di log per tracciare gli eventi legati al funzionamento del servizio IDS/IPS.

Utilizza la libreria argparse per la gestione della riga di comando e logging per la gestione dei log.

Argomenti da linea di comando:
------------------------------
-i, --interface        : Interfaccia di rete da monitorare (obbligatorio)
                         Esempio: eth0, wlan0, etc.
-c, --config           : Percorso al file di configurazione delle regole (facoltativo)
                         Default: './rules/config_rules.json'
--home-net             : Indirizzo di rete HOME_NET (es. 192.168.1.0/24, 10.0.0.0/8, singolo indirizzo IP).
                         Default : 192.168.1.0/24
command                : Comando per avviare o fermare il servizio
                         - 'start' per avviare il servizio
                         - 'stop' per fermare il servizio

Funzionalità principali:
-------------------------
1. Parsing degli argomenti da riga di comando:
   - L'interfaccia di rete da monitorare è un parametro obbligatorio.
   - Il file di configurazione delle regole è facoltativo, con un valore di default.
   - Comandi per avviare o fermare il servizio.

2. Gestione del file di log:
   - Prima di avviare il servizio, viene eseguita la pulizia del file di log, creando un nuovo file vuoto o svuotando quello esistente.
   - Il file di log si trova in '/tmp/openwrt-ids-ips.log'.

3. Avvio e arresto del servizio:
   - Se viene fornito il comando 'start', il servizio viene avviato utilizzando il ServiceManager.
   - Se viene fornito il comando 'stop', viene eseguita una logica di arresto (da implementare).

Requisiti:
-----------
- Python 3.x
- Scapy
- ServiceManager (importato come modulo esterno)
"""

import logging
from core.utils import clear_log_file, parse_arguments, setup_logging
from services.service_manager import ServiceManager



if __name__ == "__main__":
    """
    Funzione principale che gestisce l'avvio e l'arresto del servizio.
    
    1. Parse degli argomenti da riga di comando.
    2. Configura il logging.
    3. Svuota o crea il file di log.
    4. Inizializza il ServiceManager con l'interfaccia e il file di configurazione.
    5. Avvia o ferma il servizio in base al comando ricevuto.
    """
    args = parse_arguments()
    interface = args.interface
    config_file = args.config
    #home_net = args.home_net

    # Imposta il logging
    logging.basicConfig(level=logging.INFO)
    

    # Inizializzazione del service manager con la configurazione
    service_manager = ServiceManager(interface, config_file)

    if args.command == "start":
        # Svuota o crea il file di log
        clear_log_file()
        service_manager.start()

    elif args.command == "stop":
        # Logica per fermare il servizio, se necessario
        clear_log_file()
        logging.info("Comando stop ricevuto.")
        service_manager.stop()
    
    elif args.command == "update-rules":
        logging.info("#Update Rules commad !")
