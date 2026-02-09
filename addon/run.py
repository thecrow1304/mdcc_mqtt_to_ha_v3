
import json
import os
import paho.mqtt.client as mqtt
import requests
import re

HA_URL = "http://supervisor/core/api"
HA_TOKEN = os.getenv("SUPERVISOR_TOKEN")

with open("/data/options.json") as f:
    opts = json.load(f)

MQTT_SERVER = opts["mqtt_server"].replace("mqtt://", "")
MQTT_PORT = opts["mqtt_port"]
MQTT_USER = opts["mqtt_user"]
MQTT_PASS = opts["mqtt_password"]
MQTT_TOPIC = opts["mqtt_topic"]

headers = {
    "Authorization": f"Bearer {HA_TOKEN}",
    "Content-Type": "application/json",
}

# --------------------------------------------------------
# DEVICE REGISTRY SUPPORT
# --------------------------------------------------------

def register_device(device_id, sensor_info):
    url = f"{HA_URL}/devices"
    payload = {
        "config_entries": ["dynamic_mqtt_addon_v2"],
        "connections": [["device_id", device_id]],
        "identifiers": [[device_id]],
        "manufacturer": sensor_info.get("type", "Unknown"),
        "model": sensor_info.get("type", "Unknown"),
        "name": sensor_info.get("alias", device_id),
    }
    requests.post(url, headers=headers, json=payload)


# --------------------------------------------------------
# SENSOR CATEGORIZATION
# --------------------------------------------------------

def categorize_sensor(field, unit):
    f = field.lower()

    if unit.lower() in ["°c", "c"]:
        return "temperature"
    if unit.lower() in ["kwh", "mwh"]:
        return "energy"
    if unit.lower() in ["kw", "w", "watt"]:
        return "power"
    if unit.lower() in ["m³", "m3"]:
        return "volume"
    if unit.lower() in ["m³/h", "m3/h"]:
        return "volume_flow_rate"
    if unit.lower() in ["v", "volt"]:
        return "voltage"
    if unit.lower() in ["a", "ampere"]:
        return "current"

    if "error" in f or "warning" in f:
        return "problem"

    return None


# --------------------------------------------------------
# SENSOR/ENTITY CREATION
# --------------------------------------------------------

def create_or_update_entity(device_id, field, value, unit, sensor_info):
    entity_id = f"sensor.{device_id}_{field}".lower()
    entity_id = re.sub(r'[^a-z0-9_]+', '_', entity_id)

    device_class = categorize_sensor(field, unit)

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

    url = f"{HA_URL}/states/{entity_id}"
    requests.post(url, headers=headers, data=json.dumps(payload))


# --------------------------------------------------------
# MQTT CLIENT
# --------------------------------------------------------

def on_connect(client, userdata, flags, rc):
    client.subscribe(MQTT_TOPIC)


def on_message(client, userdata, msg):
    try:
        data = json.loads(msg.payload.decode())
        sensor_info = data.get("sensor", {})
        message = data.get("message", {})

        device_id = sensor_info.get("deviceId")
        if not device_id:
            return

        register_device(device_id, sensor_info)

        for key, entry in message.items():
            val = entry.get("valueNumber") or entry.get("valueString") or entry.get("valueBoolean")
            unit = entry.get("unit", "")
            create_or_update_entity(device_id, key, val, unit, sensor_info)

    except Exception as e:
        print("Error:", e)



client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
client.username_pw_set(MQTT_USER, MQTT_PASS)
client.on_connect = on_connect
client.on_message = on_message
client.connect(MQTT_SERVER, MQTT_PORT, 60)
client.loop_forever()
client.tls_set()
client.enable_logger()


