
# MDCC MQTT → Home Assistant (v3, Deep-Debug)

Diese Version enthält erweiterte Debug-Funktionen:
- Ausführliche Logs (`on_log`, `on_disconnect`, `on_subscribe`)
- Reconnect-Strategie mit Backoff (`reconnect_delay_set`)
- Keepalive 180, eindeutige Client-ID
- TLS-Unterstützung (optional) inkl. `tls_insecure` (nur Test!)
- Debug-Entitäten:
  - `sensor.mqtt_debug_last` (letzte rohen MQTT-Payload)
  - `sensor.mqtt_connection_status` (Status & letzte Fehlerursache)

## Beispiel-Konfiguration
```yaml
mqtt_server: "mqtt://broker.example.com"
mqtt_port: 8883
mqtt_user: "mqttuser"
mqtt_password: "mqttpass"
mqtt_topic: "physec/iotree-magdeburg-city-com/iot-platform/#"

# TLS
tls_enabled: true
ca_cert: "/ssl/ca.crt"      # optional, bei privater CA
client_cert: ""             # optional
client_key: ""              # optional
tls_insecure: false          # nur für Tests!

# Debug
debug: true
on_log_verbose: true         # schaltet paho interne Logs ein
```

## Hinweise
- Bei TLS in der Regel Port **8883** verwenden.
- Zertifikate im HA-Verzeichnis **/ssl** ablegen und per Pfad verweisen.
