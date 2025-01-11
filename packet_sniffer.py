from scapy.all import sniff
import logging

class PacketSniffer:
    """
    Classe per implementare un Packet Sniffer che cattura i pacchetti di rete e li inserisce in una coda per ulteriori elaborazioni.

    Attributi:
        interface (str): L'interfaccia di rete sulla quale il Packet Sniffer opererà.
        packet_queue (queue.Queue): La coda in cui i pacchetti catturati vengono inseriti per l'elaborazione successiva.

    Metodi:
        start(stop_event): Avvia il processo di sniffing dei pacchetti sull'interfaccia specificata.
        enqueue_packet(packet): Inserisce un pacchetto nella coda se questa non è piena.
    """

    def __init__(self, interface, packet_queue):
        """
        Inizializza il Packet Sniffer con l'interfaccia di rete e la coda dei pacchetti.

        Args:
            interface (str): L'interfaccia di rete da monitorare (es. "eth0", "wlan0").
            packet_queue (queue.Queue): La coda condivisa per memorizzare i pacchetti catturati.
        """
        self.interface = interface
        self.packet_queue = packet_queue

    def start(self, stop_event):
        """
        Avvia il processo di sniffing dei pacchetti. Il metodo cattura i pacchetti sulla rete 
        utilizzando l'interfaccia specificata e li invia al metodo `enqueue_packet` per l'inserimento nella coda.

        Args:
            stop_event (threading.Event): Un evento utilizzato per segnalare la terminazione del processo.
                Lo sniffing si interrompe quando `stop_event` è impostato.

        Note:
            Questo metodo utilizza la libreria Scapy per catturare i pacchetti.
            Il parametro `prn=self.enqueue_packet` consente di elaborare ogni pacchetto con il metodo `enqueue_packet`.
            Il parametro `timeout=1` garantisce che il ciclo non rimanga bloccato indefinitamente.
        """
        logging.debug(f"Avvio del packet sniffer su {self.interface}...")
        while not stop_event.is_set():  # Continua fino a quando stop_event non è impostato
            sniff(iface=self.interface, prn=self.enqueue_packet, store=False, timeout=1)
        logging.debug("Sniffer terminato.")

    def enqueue_packet(self, packet):
        """
        Inserisce un pacchetto nella coda dei pacchetti se questa non è piena. 
        Se la coda è piena, il pacchetto viene scartato e viene generato un avviso nel log.

        Args:
            packet (scapy.packet.Packet): Il pacchetto catturato dallo sniffing.

        Note:
            - La coda è utilizzata per trasferire i pacchetti catturati al modulo di analisi.
            - Se la coda è piena, il pacchetto viene ignorato per evitare di sovraccaricare il sistema.
        """
        if not self.packet_queue.full():
            self.packet_queue.put(packet)
        else:
            logging.warning("Coda piena, pacchetto scartato.")

