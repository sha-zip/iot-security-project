import json
import os


DEFAULT_REGISTRY_PATH = os.environ.get("DEVICE_REGISTRY_PATH" , "devices.json")

def load_registry(path: str= DEFAULT_REGISTRY_PATH) -> dict:
    with open(path,"r",encoding="utf-8") as f:
     return json.load(f)

def is_active(device_id: str, registry: dict) -> bool:
    dev= registry["devices"].get(device_id)
    return bool(dev) and dev.get("status") == "active"

def can_publish(device_id: str, topic: str, registry: dict) -> bool:
    if not is_active(device_id, registry):
     return False
    return topic in registry["devices"][device_id].get("allowed_publish", [])

def can_subscribe(device_id: str, topic: str, registry: dict) -> bool:
    if not is_active(device_id, registry):
     return False
    return topic in registry["devices"][device_id].get("allowed_subscribe", [])

