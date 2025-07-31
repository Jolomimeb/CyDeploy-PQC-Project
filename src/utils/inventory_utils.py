# inventory_utils.py - Simplified mock inventory data
# This module provides a minimal list of mock devices for testing the inventory system.

import json

mock_devices = [
    {"device": "IoT-Camera-1", "ip": "10.0.0.11", "type": "Camera", "status": "Online", "location": "Main Entrance", "model": "Axis P3245-LV"},
    {"device": "Printer-Office-A", "ip": "10.0.0.16", "type": "Printer", "status": "Online", "location": "Office A", "model": "Canon imageCLASS MF644Cdw"}
]

def get_mock_inventory():
    """Returns the complete inventory list for testing/discovery."""
    return mock_devices

def get_inventory_summary():
    """Returns a summary of the inventory"""
    total_devices = len(mock_devices)
    online_count = len([d for d in mock_devices if d["status"] == "Online"])
    offline_count = len([d for d in mock_devices if d["status"] == "Offline"])
    
    return {
        "total_devices": total_devices,
        "online": online_count,
        "offline": offline_count,
        "devices": mock_devices
    }