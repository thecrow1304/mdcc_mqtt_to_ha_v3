
# Dynamic MQTT Device Generator Add-on (Enhanced Version)

Dieses Repository enthält die erweiterte Version des Home Assistant Add-ons:
- Unterstützung für Home Assistant **Geräte-Registry**
- Automatische **Sensor-Kategorisierung**
- Dynamische Entitätserzeugung auf Basis des MQTT-Payloads

## Installation
1. ZIP entpacken
2. Ordner als GitHub-Repository veröffentlichen
3. In Home Assistant unter *Add-On Store > Repositories* hinzufügen
4. Add-on installieren, konfigurieren, starten

## Konfiguration
```yaml
mqtt_server: "mqtt://example.com"
mqtt_port: 1883
mqtt_user: "user"
mqtt_password: "pass"
mqtt_topic: "physec/iotree-magdeburg-city-com/iot-platform/#"
```

## Funktionen
- Automatische Gerätekreation via HA Device Registry
- Automatische Sensorerstellung pro Payload-Feld
- Automatische device_class basierend auf Einheit/Feld
- Komplette MQTT Integration
- Vollautomatisch für jede Art JSON-Datenstruktur

## Lizenz
MIT
