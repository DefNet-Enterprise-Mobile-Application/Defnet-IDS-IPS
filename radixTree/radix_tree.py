class RadixTreeNode:
    def __init__(self):
        # I figli sono memorizzati in un dizionario.
        # Ogni chiave è un carattere del prefisso.
        self.children = {}
        # Ogni nodo contiene una lista di regole applicabili.
        self.rules = []

class RadixTree:
    def __init__(self):
        # Il Radix Tree inizia con un nodo radice vuoto.
        self.root = RadixTreeNode()

    def insert(self, key, rule):
        """
        Inserisce una regola nel Radix Tree, utilizzando 'key' come prefisso.
        """
        current = self.root
        # Per ogni carattere del prefisso 'key', attraversiamo i nodi del Radix Tree.
        for char in key:
            if char not in current.children:
                current.children[char] = RadixTreeNode()  # Se non esiste il nodo, lo creiamo.
            current = current.children[char]
        # Aggiungiamo la regola all'elenco di regole del nodo finale.
        current.rules.append(rule)

    def search(self, key):
        """
        Cerca tutte le regole che corrispondono al prefisso specificato.
        """
        current = self.root
        # Per ogni carattere del prefisso 'key', attraversiamo i nodi del Radix Tree.
        for char in key:
            if char not in current.children:
                return []  # Se non esiste un nodo per il carattere, ritorniamo una lista vuota.
            current = current.children[char]
        # Ritorniamo tutte le regole corrispondenti nel nodo finale.
        return current.rules
