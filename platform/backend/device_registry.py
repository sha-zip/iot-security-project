import json
import os

DEFAULT_REGISTRY_PATH = os.environ.get("DEVICE_REGISTRY_PATH", "devices.json")


def load_registry(path: str = DEFAULT_REGISTRY_PATH) -> dict:
    if not os.path.exists(path):
        return {"devices": {}}

    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# ================= EXISTANT =================
def is_active(device_id: str, registry: dict) -> bool:
    dev = registry["devices"].get(device_id)
    return bool(dev) and dev.get("status") == "active"


def can_publish(device_id: str, topic: str, registry: dict) -> bool:
    if not is_active(device_id, registry):
        return False
    return topic in registry["devices"][device_id].get("allowed_publish", [])


def can_subscribe(device_id: str, topic: str, registry: dict) -> bool:
    if not is_active(device_id, registry):
        return False
    return topic in registry["devices"][device_id].get("allowed_subscribe", [])


# ================= AJOUT POUR SERVER =================

def is_device_active(registry: dict, device_id: str) -> bool:
    dev = registry["devices"].get(device_id)

    if not dev:
        return False

    return dev.get("status") == "active" and not dev.get("enrolled", False)


def mark_device_enrolled(device_id: str, path: str = DEFAULT_REGISTRY_PATH):
    registry = load_registry(path)

    if device_id in registry["devices"]:
        registry["devices"][device_id]["enrolled"] = True

        with open(path, "w", encoding="utf-8") as f:
            json.dump(registry, f, indent=4)

