import logging
import time

import logging
import time

class Rule:
    def __init__(self, rule_id, protocol, src_ip, dst_ip, src_port, dst_port, action, description, direction="both", flags=None, threshold=None):
        """
        :param rule_id: Identificativo univoco della regola.
        :param protocol: Protocollo (es. "TCP", "UDP").
        :param src_ip: IP sorgente (es. "192.168.1.1" o "any").
        :param dst_ip: IP di destinazione (es. "192.168.1.2" o "any").
        :param src_port: Porta sorgente (es. "80" o "any").
        :param dst_port: Porta destinazione (es. "80" o "any").
        :param action: Azione da eseguire (es. "alert", "block").
        :param description: Descrizione della regola.
        :param direction: Direzione del traffico ("in", "out", "both").
        :param flags: Lista dei flag TCP da abbinare (es. ["S", "A"] per SYN e ACK).
        :param threshold: Dizionario contenente "count" (numero di pacchetti) e "time" (tempo in secondi).
        """
        self.rule_id = rule_id
        self.protocol = protocol
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.action = action
        self.description = description
        self.direction = direction
        self.flags = flags if flags else []  # Lista di flag da controllare
        self.threshold = threshold if threshold else {"count": 1, "time": 10}  # Default threshold: 1 pacchetto in 10 secondi

    def __repr__(self):
        return f"Rule({self.rule_id}, {self.protocol}, {self.src_ip}, {self.dst_ip}, {self.src_port}, {self.dst_port}, {self.action}, {self.direction}, {self.flags}, {self.threshold})"

    @staticmethod
    def match_rule(rule, packet, packet_history):
        """
        Verifica se una regola si applica a un dato pacchetto.
        :param rule: La regola che si desidera confrontare.
        :param packet: Il pacchetto che si desidera confrontare.
        :param packet_history: Cronologia dei pacchetti per il controllo del threshold.
        :return: True se la regola si applica al pacchetto, False altrimenti.
        """
        try:
            logging.debug(f"Verifica match per la regola: {rule} con il pacchetto: {packet.summary()}")

            # Verifica IP sorgente
            if rule.src_ip != "any":
                if packet["IP"].src != rule.src_ip:
                    logging.debug(f"Il src_ip del pacchetto {packet['IP'].src} non corrisponde alla regola src_ip {rule.src_ip}")
                    return False

            # Verifica IP destinazione
            if rule.dst_ip != "any":
                if packet["IP"].dst != rule.dst_ip:
                    logging.debug(f"Il dst_ip del pacchetto {packet['IP'].dst} non corrisponde alla regola dst_ip {rule.dst_ip}")
                    return False

            # Verifica porta sorgente
            if rule.src_port != "any" and packet.haslayer("TCP"):
                if packet["TCP"].sport != rule.src_port:
                    logging.debug(f"La src_port del pacchetto {packet['TCP'].sport} non corrisponde alla regola src_port {rule.src_port}")
                    return False

            # Verifica porta destinazione
            if rule.dst_port != "any" and packet.haslayer("TCP"):
                if packet["TCP"].dport != rule.dst_port:
                    logging.debug(f"La dst_port del pacchetto {packet['TCP'].dport} non corrisponde alla regola dst_port {rule.dst_port}")
                    return False

            # Verifica la direzione
            if rule.direction == "in":
                if rule.src_ip != "any" and packet["IP"].dst != rule.src_ip:
                    logging.debug(f"Direzione 'in' non corrisponde: il pacchetto proviene da {packet['IP'].src} e non da {rule.src_ip}")
                    return False
            elif rule.direction == "out":
                if rule.src_ip != "any" and packet["IP"].src != rule.src_ip:
                    logging.debug(f"Direzione 'out' non corrisponde: il pacchetto va verso {packet['IP'].dst} ma la regola indica {rule.src_ip}")
                    return False
            elif rule.direction == "both":
                # Direzione 'both' è sempre un match
                pass
            else:
                logging.debug(f"Direzione non riconosciuta: {rule.direction}")
                return False

            # Verifica i flag TCP (es. SYN, ACK)
            if rule.flags:
                if not packet.haslayer("TCP"):
                    logging.debug("Il pacchetto non ha un layer TCP.")
                    return False
                for flag in rule.flags:
                    if flag not in packet["TCP"].flags:
                        logging.debug(f"Il pacchetto non contiene il flag {flag}.")
                        return False

            # Gestione del threshold (numero di pacchetti in un dato intervallo di tempo)
            timestamp = time.time()
            packet_history[packet["IP"].src].append(timestamp)

            # Rimuovi pacchetti più vecchi rispetto al limite di tempo
            packet_history[packet["IP"].src] = [ts for ts in packet_history[packet["IP"].src] if ts > timestamp - rule.threshold["time"]]

            # Verifica se il numero di pacchetti supera il limite (threshold)
            if len(packet_history[packet["IP"].src]) > rule.threshold["count"]:
                logging.debug(f"Superato il threshold di {rule.threshold['count']} pacchetti in {rule.threshold['time']} secondi.")
                return True

            logging.debug("La regola non corrisponde al pacchetto.")
            return False

        except Exception as e:
            logging.error(f"Errore durante il confronto della regola: {e}")
            return False
