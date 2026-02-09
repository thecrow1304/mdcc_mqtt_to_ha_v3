
import json
import os
import re
import ssl
import time
from datetime import datetime

import paho.mqtt.client as mqtt
import requests

HA_URL = "http://supervisor/core/api"
HA_TOKEN = os.getenv("SUPERVISOR_TOKEN")

with open("/data/options.json") as f:
    opts = json.load(f)

MQTT_SERVER = opts["mqtt_server"].replace("mqtt://", "").replace("mqtts://", "")
MQTT_PORT = int(opts.get("mqtt_port", 1883))
MQTT_USER = opts.get("mqtt_user", "")
MQTT_PASS = opts.get("mqtt_password", "")
MQTT_TOPIC = opts["mqtt_topic"]

TLS_ENABLED = bool(opts.get("tls_enabled", False))
TLS_INSECURE = bool(opts.get("tls_insecure", False))
CA_CERT = opts.get("ca_cert") or None
CLIENT_CERT = opts.get("client_cert") or None
CLIENT_KEY = opts.get("client_key") or None

DEBUG = bool(opts.get("debug", False))
ON_LOG_VERBOSE = bool(opts.get("on_log_verbose", False))

headers = {
    "Authorization": f"Bearer {HA_TOKEN}",
    "Content-Type": "application/json",
}

# ---------- Helper: HA sensors ----------

def ha_set_state(entity_id: str, state: str, attributes: dict = None):
    payload = {"state": state}
    if attributes:
        payload["attributes"] = attributes
    try:
        requests.post(f"{HA_URL}/states/{entity_id}", headers=headers, data=json.dumps(payload), timeout=5)
    except Exception as e:
        print(f"[HA STATE ERROR] {entity_id}: {e}")


def publish_debug_state(msg: str, topic: str):
    if not DEBUG:
        return
    ha_set_state(
        "sensor.mqtt_debug_last",
        msg,
        {"topic": topic, "timestamp": str(datetime.now())},
    )


def set_connection_status(status: str, last_error: str = ""):
    ha_set_state(
        "sensor.mqtt_connection_status",
        status,
        {"last_error": last_error, "timestamp": str(datetime.now())},
    )

# ---------- Device Registry (best effort) ----------

def register_device(device_id, sensor_info):
    if DEBUG:
        print(f"[DEBUG] Register device: {device_id} ({sensor_info.get('alias')})")
    url = f"{HA_URL}/devices"
    payload = {
        "config_entries": ["mdcc_mqtt_to_ha_v3_deepdebug"],
        "connections": [["device_id", device_id]],
        "identifiers": [[device_id]],
        "manufacturer": sensor_info.get("type", "Unknown"),
        "model": sensor_info.get("type", "Unknown"),
        "name": sensor_info.get("alias", device_id),
    }
    try:
        requests.post(url, headers=headers, json=payload, timeout=5)
    except Exception as e:
        print("[ERROR] Device register:", e)

# ---------- Categorization ----------

def categorize_sensor(field, unit):
    f = field.lower()
    u = (unit or "").lower()
    if u in ["°c", "c"]:
        return "temperature"
    if u in ["kwh", "mwh"]:
        return "energy"
    if u in ["kw", "w", "watt"]:
        return "power"
    if u in ["m³", "m3"]:
        return "volume"
    if u in ["m³/h", "m3/h"]:
        return "volume_flow_rate"
    if u in ["v", "volt"]:
        return "voltage"
    if u in ["a", "ampere"]:
        return "current"
    if "error" in f or "warning" in f:
        return "problem"
    return None

# ---------- Entity creation ----------

def create_or_update_entity(device_id, field, value, unit, sensor_info):
    entity_id = f"sensor.{device_id}_{field}".lower()
    entity_id = re.sub(r"[^a-z0-9_]+", "_", entity_id)
    device_class = categorize_sensor(field, unit)
    if DEBUG:
        print(f"[DEBUG] ENTITY {entity_id} value={value} unit={unit} class={device_class}")
    payload = {
        "state": value,
        "attributes": {
            "friendly_name": f"{sensor_info.get('alias', device_id)} {field}",
            "unit_of_measurement": unit or "",
            "device_class": device_class,
            "device": {
                "identifiers": [device_id],
                "name": sensor_info.get("alias", device_id),
                "manufacturer": sensor_info.get("type", "Unknown"),
                "model": sensor_info.get("type", "Unknown"),
            },
        },
    }
    try:
        requests.post(f"{HA_URL}/states/{entity_id}", headers=headers, data=json.dumps(payload), timeout=5)
    except Exception as e:
        print("[ERROR] Update entity:", e)

# ---------- MQTT callbacks ----------

def on_connect(client, userdata, flags, rc, properties=None):
    print(f"[INFO] Connected to MQTT (rc={rc})")
    set_connection_status("connected", "")
    client.subscribe(MQTT_TOPIC)
    print(f"[INFO] Subscribed to: {MQTT_TOPIC}")


def on_disconnect(client, userdata, rc, properties=None):
    # rc == 0 => clean disconnect, != 0 => Fehler/Netzwerk
    print(f"[WARN] Disconnected from MQTT (rc={rc})")
    set_connection_status("disconnected", f"rc={rc}")


def on_subscribe(client, userdata, mid, granted_qos, properties=None):
    print(f"[INFO] Subscribed (mid={mid}, qos={granted_qos})")


def on_message(client, userdata, msg):
    try:
        raw = msg.payload.decode()
        topic = msg.topic
        if DEBUG:
            print("---------------- MQTT MESSAGE ----------------")
            print(f"TOPIC: {topic}")
            print(raw)
            print("----------------------------------------------")
        publish_debug_state(raw, topic)

        data = json.loads(raw)
        sensor_info = data.get("sensor", {})
        message = data.get("message", {})

        device_id = sensor_info.get("deviceId")
        if not device_id:
            print("[WARNING] No deviceId in message!")
            return

        register_device(device_id, sensor_info)
        for key, entry in message.items():
            value = entry.get("valueNumber") or entry.get("valueString") or entry.get("valueBoolean")
            unit = entry.get("unit", "")
            create_or_update_entity(device_id, key, value, unit, sensor_info)

    except Exception as e:
        print("[ERROR] Failed to process message:", e)


def on_log(client, userdata, level, buf):
    # Sehr ausführliche paho-internen Logs; nur aktivieren, wenn benötigt
    if ON_LOG_VERBOSE:
        print(f"[PAHO-LOG] {level} {buf}")

# ---------- MQTT client setup ----------
client = mqtt.Client(
    mqtt.CallbackAPIVersion.VERSION2,
    client_id=f"ha_mqtt_deepdebug_{os.getpid()}",
    protocol=mqtt.MQTTv311,
    transport="tcp",
)
client.username_pw_set(MQTT_USER, MQTT_PASS)
client.enable_logger()

client.on_connect = on_connect
client.on_disconnect = on_disconnect
client.on_subscribe = on_subscribe
client.on_message = on_message
client.on_log = on_log

# Reconnect-Backoff
client.reconnect_delay_set(min_delay=1, max_delay=30)

# TLS Setup
if TLS_ENABLED:
    print("[INFO] TLS enabled")
    try:
        if CA_CERT or CLIENT_CERT or CLIENT_KEY:
            client.tls_set(
                ca_certs=CA_CERT,
                certfile=CLIENT_CERT,
                keyfile=CLIENT_KEY,
                cert_reqs=ssl.CERT_REQUIRED,
                tls_version=ssl.PROTOCOL_TLS,
            )
        else:
            client.tls_set(tls_version=ssl.PROTOCOL_TLS)
        if TLS_INSECURE:
            client.tls_insecure_set(True)
            print("[WARNING] TLS certificate validation DISABLED (tls_insecure=true)")
    except Exception as e:
        print("[ERROR] TLS setup failed:", e)

KEEPALIVE = 180

# Verbindung herstellen mit Retry-Loop
while True:
    try:
        print(f"[INFO] Connecting to MQTT {MQTT_SERVER}:{MQTT_PORT} (keepalive={KEEPALIVE}, tls={TLS_ENABLED}) ...")
        set_connection_status("connecting", "")
        client.connect(MQTT_SERVER, MQTT_PORT, KEEPALIVE)
        client.loop_forever()
    except Exception as e:
        # Hier landen u.a. Socket-Fehler: Errno 104 Connection reset by peer
        err = str(e)
        print(f"[ERROR] MQTT connect/loop failed: {err}")
        set_connection_status("error", err)
        time.sleep(5)
