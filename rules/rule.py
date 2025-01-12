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

    def matches(self, packet):
        """
        Verifica se la regola si applica a un dato pacchetto.
        :param packet: Il pacchetto che si desidera confrontare.
        :return: True se la regola si applica al pacchetto, False altrimenti.
        """
        # Verifica IP sorgente
        if self.src_ip != "any" and packet["IP"].src != self.src_ip:
            return False
        # Verifica IP destinazione
        if self.dst_ip != "any" and packet["IP"].dst != self.dst_ip:
            return False
        # Verifica porta sorgente
        if self.src_port != "any" and packet.haslayer("TCP") and packet["TCP"].sport != self.src_port:
            return False
        # Verifica porta destinazione
        if self.dst_port != "any" and packet.haslayer("TCP") and packet["TCP"].dport != self.dst_port:
            return False
        
        # Verifica la direzione
        if self.direction == "in" and packet["IP"].dst != self.src_ip:
            return False
        elif self.direction == "out" and packet["IP"].src != self.src_ip:
            return False
        elif self.direction == "both":
            # Il traffico bidirezionale è valido in entrambe le direzioni
            pass
        else:
            # Gestione della direzione non riconosciuta
            return False
        
        return True
