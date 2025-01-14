import logging
import threading
import time
from queue import Queue
from collections import defaultdict
import requests
from core.utils import DEFUALT_NOTIFICATION_ALERT_CONFIG


class NotificationManager:
    def __init__(self, notification_url=DEFUALT_NOTIFICATION_ALERT_CONFIG, buffer_time=100, max_notifications=100000):
        """
        Inizializza il NotificationManager con deduplicazione.
        
        Args:
            notification_url (str): URL del microservizio per l'invio delle notifiche.
            buffer_time (int): Intervallo di aggregazione in secondi.
            max_notifications (int): Numero massimo di notifiche da inviare per buffer.
        """
        self.notification_url = notification_url
        self.buffer_time = buffer_time
        self.max_notifications = max_notifications
        self.event_queue = Queue()
        self.lock = threading.Lock()
    
    def start(self, stop_event):
        """
        Avvia il modulo di gestione delle notifiche.

        Args:
            stop_event (threading.Event): Un evento che segnala quando terminare il processo di invio delle notifiche.
        """
        logging.info("Modulo di notifica avviato...")

        # Ciclo di gestione delle notifiche
        while not stop_event.is_set() or not self.event_queue.empty():
            try:
                time.sleep(self.buffer_time)
                events = []

                with self.lock:
                    while not self.event_queue.empty() and len(events) < self.max_notifications:
                        events.append(self.event_queue.get())

                if events:
                    deduplicated_events = self._deduplicate_events(events)
                    self._send_notification(deduplicated_events)

            except Exception as e:
                logging.error(f"Errore durante l'elaborazione delle notifiche: {e}")

        logging.info("Modulo di notifica terminato.")

    def add_event(self, event):
        """
        Aggiunge un evento alla coda delle notifiche.
        
        Args:
            event (dict): Dati dell'evento da notificare.
        """
        with self.lock:
            self.event_queue.put(event)
            logging.debug(f"Aggiunto evento alla coda: {event}")

    def _deduplicate_events(self, events):
        """
        Deduplica e aggrega eventi simili in notifiche più concise, raggruppati per ID della regola.
        
        Args:
            events (list): Lista di eventi da deduplicare.
        
        Returns:
            list: Eventi aggregati e deduplicati per ID della regola.
        """
        event_summary = defaultdict(lambda: {
            "count": 0,
            "src_ips": set(),
            "dst_ips": set(),
            "description": ""
        })

        for event in events:
            # Ottieni ID della regola, usa "unknown" se mancante
            rule_id = event.get("rule_id", "unknown")
            event_summary[rule_id]["count"] += 1
            event_summary[rule_id]["description"] = event.get("description", "No description provided")

            # Estrai IP sorgente e destinazione dal pacchetto
            packet_info = event.get("packet", "")
            if ">" in packet_info:
                src, dst = packet_info.split(">")
                event_summary[rule_id]["src_ips"].add(src.strip().split(" ")[-1])
                event_summary[rule_id]["dst_ips"].add(dst.strip().split(" ")[0])
        
        # Costruisce la lista di eventi deduplicati
        deduplicated_events = []
        for rule_id, data in event_summary.items():
            deduplicated_event = {
                "rule_id": rule_id,
                "description": data["description"],
                "total_events": data["count"],
                "unique_src_ips": list(data["src_ips"]),
                "unique_dst_ips": list(data["dst_ips"]),
            }
            deduplicated_events.append(deduplicated_event)
        
        return deduplicated_events


    def _send_notification(self, events):
        """
        Invia una notifica aggregata al microservizio.
        
        Args:
            events (list): Lista di eventi da notificare.
        """
        try:
            payload = {"events": events}
            response = requests.post(self.notification_url, json=payload)
            response.raise_for_status()
            logging.info(f"Notifica inviata: {payload}")

        except requests.RequestException as e:
            
            logging.error(f"Errore nell'invio della notifica: {e}")


