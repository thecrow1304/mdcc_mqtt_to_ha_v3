import json
import os
import re
import ssl
import time
from datetime import datetime

import paho.mqtt.client as mqtt

# ---------------------------------------------
# Load Add-on Options
# ---------------------------------------------
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
DISCOVERY_PREFIX = opts.get("discovery_prefix", "homeassistant")  # default


# ---------------------------------------------
# Helpers for debugging
# ---------------------------------------------
def log(*args):
    """Simple debug print."""
    if DEBUG:
        print("[DEBUG]", *args)


# ---------------------------------------------
# Create MQTT Discovery Config Message
# ---------------------------------------------
def publish_discovery_config(client, device_id, sensor_info, field, unit):
    """Publish MQTT Discovery config message."""
    sensor_slug = re.sub(r"[^a-zA-Z0-9_]", "_", field.lower())

    discovery_topic = (
        f"{DISCOVERY_PREFIX}/sensor/{device_id}/{sensor_slug}/config"
    )

    payload = {
        "name": f"{sensor_info.get('alias', device_id)} {field}",
        "state_topic": f"{device_id}/{field}",
        "unique_id": f"{device_id}_{sensor_slug}",
        "device": {
            "identifiers": [device_id],
            "manufacturer": sensor_info.get("type", "Unknown"),
            "model": sensor_info.get("type", "Unknown"),
            "name": sensor_info.get("alias", device_id),
        }
    }

    if unit:
        payload["unit_of_measurement"] = unit

    log("Publishing discovery config:", discovery_topic, payload)
    client.publish(discovery_topic, json.dumps(payload), retain=True)


# ---------------------------------------------
