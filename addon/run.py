import json
import os
import re
import paho.mqtt.client as mqtt
import requests
from datetime import datetime

HA_URL = "http://supervisor/core/api"
HA_TOKEN = os.getenv("SUPERVISOR_TOKEN")

with open("/data/options.json") as f:
    opts = json.load(f)

MQTT_SERVER = opts["mqtt_server"].replace("mqtt://", "")
MQTT_PORT = opts["mqtt_port"]
MQTT_USER = opts["mqtt_user"]
MQTT_PASS = opts["mqtt_password"]
MQTT_TOPIC = opts["mqtt_topic"]

DEBUG = opts.get("debug", True)

headers = {
    "Authorization": f"Bearer {HA_TOKEN}",
    "Content-Type": "application/json",
}

# --------------------------------------------------------
# Helper: HA Debug State
# --------------------------------------------------------
def publish_debug_state(msg, topic):
    """Publish the raw MQTT message as Home Assistant entity."""
    debug_payload = {
        "state": msg,
        "attributes": {
            "topic": topic,
            "timestamp": str(datetime.now())
        }
    }

    try:
        requests.post(
            f"{HA_URL}/states/sensor.mqtt_debug_last",
            headers=headers,
            data=json.dumps(debug_payload)
        )
    except Exception as e:
        print("DEBUG ENTITY ERROR:", e)


# --------------------------------------------------------
# Device Registry Support
# --------------------------------------------------------
def register_device(device_id, sensor_info):
    if DEBUG:
        print(f"[DEBUG] Register device: {device_id} ({sensor_info.get('alias')})")

    url = f"{HA_URL}/devices"
    payload = {
        "config_entries": ["mdcc_mqtt_debug_addon"],
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


# --------------------------------------------------------
# Sensor Categorization
# --------------------------------------------------------
def categorize_sensor(field, unit):
    f = field.lower()
    u = (unit or "").lower()

    # Basic categories
    mapping = {
        ("°c", "c"): "temperature",
        ("kwh", "mwh"): "energy",
        ("kw", "w", "watt"): "power",
        ("m³", "m3"): "volume",
        ("m³/h", "m3/h"): "volume_flow_rate",
        ("v", "volt"): "voltage",
        ("a", "ampere"): "current",
    }

    for keys, value in mapping.items():
        if u in keys:
            return value

    if "error" in f or "warning" in f:
        return "problem"

    return None


# --------------------------------------------------------
# Entity Creation
# --------------------------------------------------------
def create_or_update_entity(device_id, field, value, unit, sensor_info):
    entity_id = f"sensor.{device_id}_{field}".lower()
    entity_id = re.sub(r"[^a-z0-9_]+", "_", entity_id)

    device_class = categorize_sensor(field, unit)

    if DEBUG:
        print(f"[DEBUG] CREATE ENTITY: {entity_id}")
        print(f"        Value = {value}, Unit = {unit}, DeviceClass = {device_class}")

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
            }
        }
    }

    try:
        requests.post(
            f"{HA_URL}/states/{entity_id}",
            headers=headers,
            data=json.dumps(payload)
        )
    except Exception as e:
        print("[ERROR] Update entity:", e)


# --------------------------------------------------------
# MQTT CALLBACKS
# --------------------------------------------------------
def on_connect(client, userdata, flags, rc):
    print("[INFO] Connected to MQTT.")
    client.subscribe(MQTT_TOPIC)
    print(f"[INFO] Subscribed to: {MQTT_TOPIC}")


def on_message(client, userdata, msg):
    try:
        raw = msg.payload.decode()
        topic = msg.topic

        # DEBUG print
        print("---------------------------------------------------")
        print(f"[MQTT] Incoming message on {topic}:")
        print(raw)
        print("---------------------------------------------------")

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


# --------------------------------------------------------
# MQTT Client Setup (Callback API v2)
# --------------------------------------------------------

client = mqtt.Client(
    mqtt.CallbackAPIVersion.VERSION2,
    client_id=f"ha_mqtt_tls_{os.getpid()}",
    protocol=mqtt.MQTTv311,
    transport="tcp",
)
client.username_pw_set(MQTT_USER, MQTT_PASS)
client.enable_logger()

if TLS_ENABLED:
    # Nutzt wahlweise eigene CA/Client-Zertifikate oder System-CAs
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

    if TLS_INSECURE:  # Nur für Tests!
        client.tls_insecure_set(True)

client.on_connect = on_connect
client.on_message = on_message

print("[INFO] Connecting to MQTT...")
client.connect(MQTT_SERVER, MQTT_PORT, 60)
client.loop_forever()