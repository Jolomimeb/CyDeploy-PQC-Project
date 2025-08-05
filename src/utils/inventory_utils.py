# This is the mock data that gets sent to the server
import json

mock_devices = [
    {"device": "IoT-Camera-1", "ip": "10.0.0.11", "type": "Camera", "status": "Online", "location": "Main Entrance", "model": "Axis P3245-LV"},
    {"device": "Printer-Office-A", "ip": "10.0.0.16", "type": "Printer", "status": "Online", "location": "Office A", "model": "Canon imageCLASS MF644Cdw"}
]

def get_mock_inventory():
    # i just return the mock devices
    return mock_devices
