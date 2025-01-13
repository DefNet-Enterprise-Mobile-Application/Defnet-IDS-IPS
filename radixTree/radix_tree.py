import logging


class RadixTreeNode:
    """
    Nodo base per la struttura Radix Tree.

    Attributi:
    -----------
    children (dict): Dizionario che memorizza i nodi figli, con le chiavi come caratteri e i valori come nodi.
    rules (list): Lista delle regole associate al nodo.
    """

    def __init__(self):
        self.children = {}
        self.rules = []

class RadixTree:
    """
    Implementazione di una Radix Tree (albero delle radici) per la gestione delle regole.

    La Radix Tree è una struttura dati ottimizzata per la gestione e la ricerca di regole in base a prefissi.
    Ogni nodo della Radix Tree può contenere più regole e i prefissi sono utilizzati per organizzare le regole.

    Attributi:
    -----------
    root (RadixTreeNode): Il nodo radice della Radix Tree.

    Metodi:
    --------
    insert(key, rule):
        Inserisce una regola nella Radix Tree, utilizzando 'key' come prefisso.
        Ottimizza l'inserimento unendo nodi quando possibile.

    search(key):
        Cerca tutte le regole che corrispondono al prefisso specificato.
        Restituisce regole con wildcard 'any' se non trova corrispondenze esatte.

    remove_rule(key, rule):
        Rimuove una regola associata a un prefisso specifico.
        Restituisce True se la regola è stata rimossa, False altrimenti.

    display(node=None, prefix=""):
        Stampa la struttura del Radix Tree (utile per il debug).

    _collect_rules_with_wildcards(node):
        Raccoglie tutte le regole con wildcard ('any') nel Radix Tree.

    _is_wildcard_rule(rule):
        Verifica se una regola contiene wildcard ('any').
    """

    def __init__(self):
        """
        Inizializza la Radix Tree con un nodo radice vuoto.
        """
        self.root = RadixTreeNode()

    def insert(self, key: str, rule: object):
            """
            Inserisce una regola nella Radix Tree, utilizzando 'key' come prefisso.
            Consente regole duplicate solo se l'ID della regola è diverso.

            Argomenti:
            ----------
            key (str): Il prefisso (stringa) da utilizzare per l'inserimento della regola.
            rule (object): La regola da inserire nella struttura dati.
            """
            current = self.root
            i = 0
            while i < len(key):
                char = key[i]
                if char in current.children:
                    current = current.children[char]
                else:
                    new_node = RadixTreeNode()
                    current.children[char] = new_node
                    current = new_node
                i += 1

            # Verifica duplicati basati sull'ID della regola
            for existing_rule in current.rules:
                if getattr(existing_rule, 'rule_id', None) == getattr(rule, 'rule_id', None):
                    logging.info(f"Regola con ID {rule.id} già presente per il prefisso {key}. Ignorata.")
                    return

            # Aggiunge la regola se non ci sono duplicati con lo stesso ID
            current.rules.append(rule)
            logging.info(f"Regola aggiunta per il prefisso {key}: {rule}")

    def search(self, key: str) -> list:
        """
        Cerca tutte le regole che corrispondono al prefisso specificato.
        Restituisce regole con wildcard 'any' se non trova corrispondenze esatte.

        Argomenti:
        ----------
        key (str): Il prefisso da cercare nel Radix Tree.

        Restituisce:
        -----------
        list: Una lista delle regole che corrispondono al prefisso.
              Includendo anche le regole con wildcard ('any') se non trovate corrispondenze esatte.
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

        Argomenti:
        ----------
        node (RadixTreeNode): Il nodo corrente da esplorare.

        Restituisce:
        -----------
        list: Una lista di regole che contengono la wildcard ('any').
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

        Argomenti:
        ----------
        rule (object): La regola da verificare.

        Restituisce:
        -----------
        bool: True se la regola contiene una wildcard ('any'), False altrimenti.
        """
        return (
            getattr(rule, 'src_ip', None) == 'any' or
            getattr(rule, 'dst_ip', None) == 'any' or
            getattr(rule, 'src_port', None) == 'any' or
            getattr(rule, 'dst_port', None) == 'any'
        )

    def remove_rule(self, key: str, rule: object) -> bool:
        """
        Rimuove una regola associata a un prefisso specifico.

        Argomenti:
        ----------
        key (str): Il prefisso associato alla regola da rimuovere.
        rule (object): La regola da rimuovere.

        Restituisce:
        -----------
        bool: True se la regola è stata rimossa, False se non è stata trovata.
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

        Argomenti:
        ----------
        node (RadixTreeNode, opzionale): Nodo da cui partire la visualizzazione. Se non fornito, si parte dalla radice.
        prefix (str, opzionale): Prefisso corrente durante la traversata dell'albero. Default è una stringa vuota.
        """
        if node is None:
            node = self.root
        if node.rules:
            print(f"Prefisso: {prefix}, Regole: {node.rules}")
        for char, child in node.children.items():
            self.display(child, prefix + char)
