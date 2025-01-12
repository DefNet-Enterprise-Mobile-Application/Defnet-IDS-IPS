#!/bin/bash

# Percorso al file Python (ad esempio /home/udm-root/OpenWRT-IDS-IPS/main.py)
SERVICE_SCRIPT="/root/Defnet-IDS-IPS/main.py"
LOG_FILE="/tmp/openwrt-ids-ips.log"  # File di log
SERVICE_PID_FILE="/tmp/openwrt-ids-ips.pid"  # File per memorizzare il PID

# Imposta un'interfaccia di rete predefinita (modifica se necessario)
DEFAULT_INTERFACE="eth0"

# Funzione per gestire gli argomenti passati allo script
get_interface() {
    # Se l'utente ha passato un argomento per -i, usalo, altrimenti usa il valore di default
    INTERFACE="$1"
    if [ -z "$INTERFACE" ]; then
        INTERFACE="$DEFAULT_INTERFACE"
    fi
    echo "$INTERFACE"
}

start_service() {
    # Ottieni l'interfaccia da utilizzare (di default eth0 se non specificato)
    INTERFACE=$(get_interface "$2")

    if [ -f "$SERVICE_PID_FILE" ]; then
        PID=$(cat "$SERVICE_PID_FILE")
        if ps $PID > /dev/null; then
            echo "[INFO] Il servizio è già in esecuzione con PID $PID."
            return 0
        else
            echo "[INFO] PID trovato, ma il processo non è in esecuzione. Rimuovendo il PID obsoleto."
            rm -f "$SERVICE_PID_FILE"
        fi
    fi

    # Verifica che non ci siano processi duplicati prima di avviare
    if ps | grep "$SERVICE_SCRIPT" | grep -v "grep" > /dev/null; then
        echo "[ERROR] Il servizio è già in esecuzione."
        return 1
    fi

    echo "Avvio del servizio IDS/IPS sull'interfaccia $INTERFACE..."
    # Avvia il servizio come demone in background e salva il PID nel file
    python3 "$SERVICE_SCRIPT" -i "$INTERFACE" start >> "$LOG_FILE" 2>&1 &
    echo $! > "$SERVICE_PID_FILE"  # Salva il PID del processo
    echo "Servizio avviato in background. I log sono disponibili in $LOG_FILE."
    echo "Se vuoi seguire il traffico di rete digita tail -f /tmp/openwrt-ids-ips.log"
}

stop_service() {
    if [ -f "$SERVICE_PID_FILE" ]; then
        PID=$(cat "$SERVICE_PID_FILE")
        if kill -0 $PID > /dev/null; then
            echo "Fermando il servizio con PID $PID..."
            kill -SIGTERM "$PID"
            rm -f "$SERVICE_PID_FILE"  # Rimuove il file PID
            echo "Servizio fermato."
        else
            echo "[ERROR] Il processo con PID $PID non è in esecuzione."
            rm -f "$SERVICE_PID_FILE"  # Rimuove il PID obsoleto
        fi
    else
        echo "[INFO] Nessun PID trovato nel file. Esecuzione del comando pkill per terminare il servizio."
    fi

    # Uccidi tutte le istanze del servizio con il nome script specificato
    echo "[INFO] Tutti i processi del servizio $SERVICE_SCRIPT sono stati arrestati."
}

case "$1" in
  start)
    start_service "$@"
    ;;
  stop)
    stop_service
    ;;
  *)
    echo "Uso: $0 {start|stop} [interfaccia]"
    exit 1
    ;;
esac