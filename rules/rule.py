import logging


class Rule:
    def __init__(self, rule_id, protocol, src_ip, dst_ip, src_port, dst_port, action, description, direction="both"):
        """
        :param rule_id: Identificativo univoco della regola.
        :param protocol: Protocollo (es. "TCP", "UDP").
        :param src_ip: IP sorgente (es. "192.168.1.1" o "any").
        :param dst_ip: IP di destinazione (es. "192.168.1.2" o "any").
        :param src_port: Porta sorgente (es. "80" o "any").
        :param dst_port: Porta destinazione (es. "80" o "any").
        :param action: Azione da eseguire (es. "allert", "block").
        :param description: Descrizione della regola.
        :param direction: Direzione del traffico ("in", "out", "both").
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

    def __repr__(self):
        return f"Rule({self.rule_id}, {self.protocol}, {self.src_ip}, {self.dst_ip}, {self.src_port}, {self.dst_port}, {self.action}, {self.direction})"

    @staticmethod
    def match_rule(rule, packet):
        """
        Verifica se una regola si applica a un dato pacchetto.
        :param rule: La regola che si desidera confrontare.
        :param packet: Il pacchetto che si desidera confrontare.
        :return: True se la regola si applica al pacchetto, False altrimenti.
        """
        try:
            logging.debug(f"Verifica match per la regola: {rule} con il pacchetto: {packet.summary()}")

            # Verifica IP sorgente
            if rule.src_ip != "any":
                if packet["IP"].src != rule.src_ip:
                    logging.debug(f"Il src_ip del pacchetto {packet['IP'].src} non corrisponde alla regola src_ip {rule.src_ip}")
                    return False
                else:
                    logging.debug(f"Il src_ip del pacchetto {packet['IP'].src} corrisponde alla regola src_ip {rule.src_ip}")

            # Verifica IP destinazione
            if rule.dst_ip != "any":
                if packet["IP"].dst != rule.dst_ip:
                    logging.debug(f"Il dst_ip del pacchetto {packet['IP'].dst} non corrisponde alla regola dst_ip {rule.dst_ip}")
                    return False
                else:
                    logging.debug(f"Il dst_ip del pacchetto {packet['IP'].dst} corrisponde alla regola dst_ip {rule.dst_ip}")

            # Verifica porta sorgente
            if rule.src_port != "any" and packet.haslayer("TCP"):
                if packet["TCP"].sport != rule.src_port:
                    logging.debug(f"La src_port del pacchetto {packet['TCP'].sport} non corrisponde alla regola src_port {rule.src_port}")
                    return False
                else:
                    logging.debug(f"La src_port del pacchetto {packet['TCP'].sport} corrisponde alla regola src_port {rule.src_port}")

            # Verifica porta destinazione
            if rule.dst_port != "any" and packet.haslayer("TCP"):
                if packet["TCP"].dport != rule.dst_port:
                    logging.debug(f"La dst_port del pacchetto {packet['TCP'].dport} non corrisponde alla regola dst_port {rule.dst_port}")
                    return False
                else:
                    logging.debug(f"La dst_port del pacchetto {packet['TCP'].dport} corrisponde alla regola dst_port {rule.dst_port}")

            # Verifica la direzione
            if rule.direction == "in":
                if rule.src_ip == "any":
                    logging.debug(f"La direzione 'in' non corrisponde: il dst_ip del pacchetto {packet['IP'].dst} non è uguale a src_ip della regola {rule.src_ip}")
                    return True
                elif packet["IP"].dst != rule.src_ip:
                    logging.debug(f"La direzione 'in' corrisponde: il dst_ip del pacchetto {packet['IP'].dst} ma è uguale a src_ip della regola {rule.src_ip}")
                    return False
                else:
                    logging.debug(f"La direzione 'in' corrisponde: il dst_ip del pacchetto {packet['IP'].dst} è uguale a src_ip della regola {rule.src_ip}")

            elif rule.direction == "out":
                if rule.src_ip == "any":
                    logging.debug(f"La direzione 'out' non corrisponde: il src_ip del pacchetto {packet['IP'].src} non è uguale a src_ip della regola {rule.src_ip}")
                    return True
                elif packet["IP"].src != rule.src_ip:
                    logging.debug(f"La direzione 'out' corrisponde: il src_ip del pacchetto {packet['IP'].src} ma è uguale a src_ip della regola {rule.src_ip}")
                    return False
                else:
                    logging.debug(f"La direzione 'out' corrisponde: il src_ip del pacchetto {packet['IP'].src} è uguale a src_ip della regola {rule.src_ip}")

            elif rule.direction == "both":
                logging.debug(f"Direzione 'both': il traffico è accettato in entrambe le direzioni per la regola {rule}")

            else:
                logging.debug(f"Direzione non riconosciuta: {rule.direction}")
                return False

            logging.debug("La regola corrisponde al pacchetto.")
            return True

        except Exception as e:
            logging.error(f"Errore durante il confronto della regola: {e}")
            return False