class Rule:
    def __init__(self, rule_id, protocol, src_ip, dst_ip, src_port, dst_port, action, description):
        self.rule_id = rule_id
        self.protocol = protocol
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.action = action
        self.description = description

    def __repr__(self):
        return f"Rule({self.rule_id}, {self.protocol}, {self.src_ip}, {self.dst_ip}, {self.src_port}, {self.dst_port}, {self.action})"

    def matches(self, packet):
        """
        Verifica se la regola si applica a un dato pacchetto.
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
        return True
