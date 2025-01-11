import argparse
import logging
from service_manager import ServiceManager

def parse_arguments():
    parser = argparse.ArgumentParser(description="Sniffer di rete con Scapy")
    parser.add_argument(
        "-i", "--interface", 
        required=True, 
        help="Interfaccia di rete da analizzare (es. eth0, wlan0, etc.)"
    )
    parser.add_argument(
        "command", 
        choices=["start", "stop"], 
        help="Comando per avviare o fermare il servizio"
    )
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_arguments()
    interface = args.interface

    service_manager = ServiceManager(interface)

    if args.command == "start":
        service_manager.start()
    elif args.command == "stop":
        # Logica per fermare il servizio, se necessario
        logging.info("Comando stop ricevuto.")

