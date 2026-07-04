# tinyDLT
Codebase to build tiny real-time local DLT for vehicular system

IOTA Tangle - Quick start
Files included:
node_server.py (FastAPI node)
visualizer.html (frontend visualizer)
miner.py (optional Python miner/sender)
ESP8266_Tangle_PoC.ino (Arduino sketch for ESP8266)
requirements.txt
tangle_store.json (auto-created at runtime)

Quick steps:
Create a Python virtualenv and install requirements on linux:
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
make ready the Linux system:
sudo apt update
sudo apt install -y mosquitto mosquitto-clients python3-pip sqlite3
pip3 install paho-mqtt tinydb
pip install "paho-mqtt<2.0"
pip install networkx
pip install matplotlib
pip install pyvis
pip install --upgrade paho-mqtt
Enable MQTT pubsub by:
sudo systemctl enable --now mosquitto
Confirm the activation by:
mosquitto_sub -h localhost -t '$SYS/#' -C 1
Start the RSU coordinator Node on ubuntu linux by:
python node_server.py
TO check GUI DAG explorer on browser: open 'tangle.html'
Important Note: delete the tangle.db file if exist to start a fresh run.

Programming the ESP32/esp8266 Vehicle node:
Add necessary ESP32/esp8266 preferences, pub/sub library, ESP32/esp8266 library in library manager and ESP32/esp8266 board in board manager.
Edit the WiFi credentials in latest_version.ino file: ssid and password of wifi hotspot
execute'ifconfig' on RSU linux terminal and pick the 'inet' address of 'wl01' and add it as 'mqtt_server = "..."'
flash `ESP8266_latest_version.ino
Optionally run `vehicle_simulator.py` to generate test transactions from your PC.
The server stores the tangle in `tangle_store.json` and broadcasts updates over WebSocket to the visualizer.

Notes:
line 187 in server: client = mqtt.Client(client_id="rsu_dlt_server")
line 18 in vehicle _simulator: client = mqtt.Client(client_id=NODE_ID)

