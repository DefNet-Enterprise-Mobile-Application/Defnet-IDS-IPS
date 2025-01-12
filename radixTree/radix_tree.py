import logging


class RadixTreeNode:
    def __init__(self):
        self.children = {}
        self.rules = []

class RadixTree:
    def __init__(self):
        self.root = RadixTreeNode()

    def insert(self, key: str, rule: object):
        """
        Inserisce una regola nel Radix Tree, utilizzando 'key' come prefisso.
        Ottimizza l'inserimento unendo nodi quando possibile.
        """
        current = self.root
        i = 0
        while i < len(key):
            char = key[i]
            # Se il nodo esiste, attraversiamo il nodo
            if char in current.children:
                current = current.children[char]
                i += 1
            else:
                # Se il nodo non esiste, lo creiamo
                new_node = RadixTreeNode()
                current.children[char] = new_node
                current = new_node
                i += 1
        current.rules.append(rule)

    def search(self, key: str) -> list:
        """
        Cerca tutte le regole che corrispondono al prefisso specificato.
        Restituisce regole con wildcard 'any' se non trova corrispondenze esatte.
        """
        logging.debug(f"Inizio ricerca per il prefisso: {key}")
        current = self.root
        i = 0

        # Navigazione nel Radix Tree
        while i < len(key):
            char = key[i]
            if char not in current.children:
                logging.debug(f"Nodo non trovato per il prefisso {key[:i+1]}. Verifica wildcard.")
                # Se non esiste una corrispondenza esatta, cerca regole con 'any'
                wildcard_rules = self._collect_rules_with_wildcards(self.root)
                logging.debug(f"Regole con wildcard trovate: {wildcard_rules}")
                return wildcard_rules
            current = current.children[char]
            i += 1

        # Ritorna le regole del nodo finale, includendo quelle con 'any'
        logging.debug(f"Regole trovate per il prefisso {key}: {current.rules}")
        return current.rules + self._collect_rules_with_wildcards(self.root)

    def _collect_rules_with_wildcards(self, node) -> list:
        """
        Raccoglie tutte le regole con wildcard ('any') nel Radix Tree.
        """
        rules_with_wildcards = []
        if node.rules:
            for rule in node.rules:
                # Aggiungi regole con wildcard 'any'
                if self._is_wildcard_rule(rule):
                    rules_with_wildcards.append(rule)
        for child in node.children.values():
            rules_with_wildcards.extend(self._collect_rules_with_wildcards(child))
        return rules_with_wildcards

    def _is_wildcard_rule(self, rule) -> bool:
        """
        Verifica se una regola contiene wildcard ('any').
        """
        return (
            getattr(rule, 'src_ip', None) == 'any' or
            getattr(rule, 'dst_ip', None) == 'any' or
            getattr(rule, 'src_port', None) == 'any' or
            getattr(rule, 'dst_port', None) == 'any'
        )


    def remove_rule(self, key: str, rule: object) -> bool:
        """
        Rimuove una regola specifica associata a un prefisso, se esiste.
        Restituisce True se la regola è stata rimossa, altrimenti False.
        """
        current = self.root
        i = 0
        while i < len(key):
            char = key[i]
            if char not in current.children:
                return False  # Non esiste il nodo per il prefisso
            current = current.children[char]
            i += 1
        if rule in current.rules:
            current.rules.remove(rule)
            return True
        return False

    def display(self, node=None, prefix=""):
        """
        Stampa la struttura del Radix Tree (utile per il debug).
        """
        if node is None:
            node = self.root
        if node.rules:
            print(f"Prefisso: {prefix}, Regole: {node.rules}")
        for char, child in node.children.items():
            self.display(child, prefix + char)
