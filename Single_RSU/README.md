# Tiny DLT - Quick start

Files included:
- Tangle_Server_Node.py (FastAPI node)
- Tangle.html (frontend visualizer)
- miner.py (optional Python miner/sender)
- ESP8266_Tangle_Node.ino (Arduino sketch for ESP8266/ESP32)
- requirements.txt
- tangle_store.json (auto-created at runtime)
- performance_evaluation.py
- miner.py


Quick steps:
1. Create a Python virtualenv and install requirements on linux:
	python -m venv venv
	source venv/bin/activate
	pip install -r requirements.txt
   
2. make ready the Linux system:
 	sudo apt update
	sudo apt install -y mosquitto mosquitto-clients python3-pip sqlite3
	pip3 install paho-mqtt tinydb
	pip install "paho-mqtt<2.0" 
	pip install networkx
	pip install matplotlib
	pip install pyvis
	pip install --upgrade paho-mqtt

3. Enable MQTT pubsub by:
	sudo systemctl enable --now mosquitto
   Confirm the activation by:
   	mosquitto_sub -h localhost -t '$SYS/#' -C 1

4. Start the RSU coordinator Node on ubuntu linux by:
   	python Tangle_Server_Node.py 
   	TO check GUI DAG explorer on browser: open 'tangle.html'  	
   Important Note: delete the tangle.db file if exist to start a fresh run.


5. Programming the ESP32/esp8266 Vehicle node:
	Add necessary ESP32/esp8266 preferences, pub/sub library, ESP32/esp8266 library in library manager and ESP32/esp8266 board in board manager.
	Edit the WiFi credentials in latest_version.ino file: ssid and password of wifi hotspot
	execute'ifconfig' on RSU linux terminal and pick the 'inet' address of 'wl01' and add it as 'mqtt_server = "**.**.**.**"'
	flash `ESP8266_latest_version.ino
6. Optionally run `vehicle_simulator.py` to generate test transactions from your PC.
7. The server stores the tangle in `tangle_store.json` and broadcasts updates over WebSocket to the visualizer.


=======================================on errors========================================
Error:	10:29:23.461 -> 🔌 Connecting to MQTT...failed, rc=-2
 	10:29:25.471 -> 🔌 Connecting to MQTT...failed, rc=-2
 
Solution: 
 Run:'sudo netstat -tulpn | grep 1883'
 You will likely see something like:tcp   0   0 127.0.0.1:1883   0.0.0.0:*   LISTEN.
 then: Open Mosquitto config: sudo gedit /etc/mosquitto/mosquitto.conf
 Add these lines at the end of the file:
         listener 1883
        allow_anonymous true
        
Make sure there is NO line like:
    bind_address 127.0.0.1      ; If it exists, remove it.
    
Restart MQTT by:'sudo systemctl restart mosquitto'

recheck it by: sudo netstat -tulpn | grep 1883 
Now you should see: tcp   0   0 0.0.0.0:1883   0.0.0.0:*   LISTEN
---------------------------------------------------------------
ARDUINO LIBRARIES NEEDED:
1. PubSubClient by Nick O'Leary
2. board: esp32 by espressif   select board as: DOIT ESP32 DEVKIT V1 / esp8266 BY ESP8266 community, select board as: generic esp8266 module
3. ArduinoJson by Benoit Blanchon
4. prferences http://arduino.esp8266.com/stable/package_esp8266com_index.json
https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json

