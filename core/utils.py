import logging

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
