import logging

def setup_logging(log_file="/tmp/openwrt-ids-ips.log"):
    logging.basicConfig(
        level=logging.DEBUG,  # Aumentato a DEBUG per vedere più dettagli
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),  # Scrive solo nel file di log
        ]
    )
