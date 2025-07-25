# inventory_utils.py - Generates comprehensive mock inventory data
# This module provides a large, static list of mock devices for testing the inventory system.
# The inventory includes various device types, locations, and statuses to simulate a real environment.

import random

mock_devices = [
    # Cameras
    {"device": "IoT-Camera-1", "ip": "10.0.0.11", "type": "Camera", "status": "Online", "location": "Main Entrance", "model": "Axis P3245-LV"},
    {"device": "IoT-Camera-2", "ip": "10.0.0.12", "type": "Camera", "status": "Online", "location": "Parking Lot", "model": "Hikvision DS-2CD2143G0-I"},
    {"device": "Security-Cam-A", "ip": "10.0.0.13", "type": "Camera", "status": "Offline", "location": "Loading Dock", "model": "Dahua IPC-HFW4431R-Z"},
    {"device": "Parking-Cam-B", "ip": "10.0.0.15", "type": "Camera", "status": "Online", "location": "Employee Parking", "model": "Bosch FLEXIDOME IP starlight 7000 VR"},
    {"device": "Hallway-Cam-1", "ip": "10.0.0.19", "type": "Camera", "status": "Online", "location": "Floor 1 Hallway", "model": "Axis P3245-LV"},
    {"device": "Stairwell-Cam-A", "ip": "10.0.0.20", "type": "Camera", "status": "Online", "location": "Stairwell A", "model": "Hikvision DS-2CD2143G0-I"},
    {"device": "Emergency-Exit-Cam", "ip": "10.0.0.21", "type": "Camera", "status": "Maintenance", "location": "Emergency Exit", "model": "Dahua IPC-HFW4431R-Z"},
    
    # Printers
    {"device": "Printer-23", "ip": "10.0.0.14", "type": "Printer", "status": "Idle", "location": "Floor 1 East", "model": "HP LaserJet Pro M404dn"},
    {"device": "Printer-Office-A", "ip": "10.0.0.16", "type": "Printer", "status": "Printing", "location": "Office A", "model": "Canon imageCLASS MF644Cdw"},
    {"device": "Color-Printer-B", "ip": "10.0.0.17", "type": "Printer", "status": "Online", "location": "Design Department", "model": "Epson EcoTank ET-4760"},
    {"device": "Network-Printer-C", "ip": "10.0.0.18", "type": "Printer", "status": "Error", "location": "Floor 2 West", "model": "Brother HL-L8360CDW"},
    {"device": "Reception-Printer", "ip": "10.0.0.25", "type": "Printer", "status": "Online", "location": "Reception", "model": "HP OfficeJet Pro 9015e"},
    {"device": "Large-Format-Printer", "ip": "10.0.0.26", "type": "Printer", "status": "Idle", "location": "Print Shop", "model": "Epson SureColor P800"},
    
    # Laptops
    {"device": "Employee-Laptop", "ip": "10.0.0.51", "type": "Laptop", "status": "Online", "location": "Desk 101", "model": "Dell Latitude 7420"},
    {"device": "Manager-Laptop-01", "ip": "10.0.0.52", "type": "Laptop", "status": "Online", "location": "Manager Office", "model": "MacBook Pro 14"},
    {"device": "Dev-Laptop-15", "ip": "10.0.0.53", "type": "Laptop", "status": "Offline", "location": "Dev Team Area", "model": "ThinkPad X1 Carbon"},
    {"device": "HR-Laptop-07", "ip": "10.0.0.54", "type": "Laptop", "status": "Online", "location": "HR Department", "model": "HP EliteBook 840"},
    {"device": "Sales-Laptop-03", "ip": "10.0.0.55", "type": "Laptop", "status": "Online", "location": "Sales Floor", "model": "Surface Laptop 4"},
    {"device": "Finance-Laptop-12", "ip": "10.0.0.56", "type": "Laptop", "status": "Maintenance", "location": "Finance Office", "model": "Dell XPS 13"},
    {"device": "Executive-Laptop", "ip": "10.0.0.57", "type": "Laptop", "status": "Online", "location": "Executive Suite", "model": "MacBook Pro 16"},
    {"device": "Temp-Laptop-A", "ip": "10.0.0.58", "type": "Laptop", "status": "Idle", "location": "Storage", "model": "Lenovo ThinkPad E15"},
    
    # Servers
    {"device": "Web-Server-01", "ip": "10.0.1.10", "type": "Server", "status": "Online", "location": "Server Room", "model": "Dell PowerEdge R740"},
    {"device": "Database-Server", "ip": "10.0.1.11", "type": "Server", "status": "Online", "location": "Server Room", "model": "HP ProLiant DL380"},
    {"device": "File-Server-Main", "ip": "10.0.1.12", "type": "Server", "status": "Maintenance", "location": "Server Room", "model": "Dell PowerEdge R640"},
    {"device": "Backup-Server", "ip": "10.0.1.13", "type": "Server", "status": "Online", "location": "Server Room", "model": "Synology DS1621+"},
    {"device": "Email-Server", "ip": "10.0.1.14", "type": "Server", "status": "Online", "location": "Server Room", "model": "Dell PowerEdge R440"},
    {"device": "Development-Server", "ip": "10.0.1.15", "type": "Server", "status": "Online", "location": "Server Room", "model": "HP ProLiant ML350"},
    
    # IoT Devices
    {"device": "Smart-Thermostat-1", "ip": "10.0.2.20", "type": "IoT", "status": "Online", "location": "Main Floor", "model": "Honeywell T9"},
    {"device": "Smart-Thermostat-2", "ip": "10.0.2.24", "type": "IoT", "status": "Online", "location": "Second Floor", "model": "Nest Learning"},
    {"device": "Motion-Sensor-A", "ip": "10.0.2.21", "type": "IoT", "status": "Online", "location": "Lobby", "model": "Philips Hue Motion"},
    {"device": "Motion-Sensor-B", "ip": "10.0.2.25", "type": "IoT", "status": "Online", "location": "Hallway 2", "model": "Philips Hue Motion"},
    {"device": "Motion-Sensor-C", "ip": "10.0.2.26", "type": "IoT", "status": "Offline", "location": "Parking Garage", "model": "Aeotec MultiSensor 6"},
    {"device": "Door-Lock-Main", "ip": "10.0.2.22", "type": "IoT", "status": "Online", "location": "Main Entrance", "model": "August Smart Lock Pro"},
    {"device": "Door-Lock-Side", "ip": "10.0.2.27", "type": "IoT", "status": "Online", "location": "Side Entrance", "model": "Yale Assure Lock"},
    {"device": "Door-Lock-Emergency", "ip": "10.0.2.28", "type": "IoT", "status": "Maintenance", "location": "Emergency Exit", "model": "Schlage Encode Plus"},
    {"device": "Air-Quality-Monitor", "ip": "10.0.2.23", "type": "IoT", "status": "Offline", "location": "Conference Room", "model": "Awair Element"},
    {"device": "Smart-Light-1", "ip": "10.0.2.29", "type": "IoT", "status": "Online", "location": "Reception", "model": "Philips Hue Bridge"},
    {"device": "Smart-Light-2", "ip": "10.0.2.30", "type": "IoT", "status": "Online", "location": "Meeting Room A", "model": "LIFX Z Strip"},
    {"device": "Smart-Speaker-1", "ip": "10.0.2.31", "type": "IoT", "status": "Online", "location": "Break Room", "model": "Amazon Echo Dot"},
    {"device": "Water-Leak-Sensor", "ip": "10.0.2.32", "type": "IoT", "status": "Online", "location": "Server Room", "model": "Aeotec Water Sensor 6"},
    {"device": "Smoke-Detector-1", "ip": "10.0.2.33", "type": "IoT", "status": "Online", "location": "Kitchen", "model": "Nest Protect"},
    {"device": "Smart-Camera-Door", "ip": "10.0.2.34", "type": "IoT", "status": "Online", "location": "Front Door", "model": "Ring Video Doorbell"},
    
    # Network Equipment
    {"device": "Router-Main", "ip": "10.0.0.1", "type": "Network", "status": "Online", "location": "Server Room", "model": "Cisco ISR 4331"},
    {"device": "Switch-Floor-1", "ip": "10.0.0.2", "type": "Network", "status": "Online", "location": "Floor 1 IDF", "model": "Cisco Catalyst 2960-X"},
    {"device": "Switch-Floor-2", "ip": "10.0.0.5", "type": "Network", "status": "Online", "location": "Floor 2 IDF", "model": "Cisco Catalyst 2960-X"},
    {"device": "Access-Point-A", "ip": "10.0.0.3", "type": "Network", "status": "Online", "location": "Reception Area", "model": "Cisco Aironet 2802i"},
    {"device": "Access-Point-B", "ip": "10.0.0.6", "type": "Network", "status": "Online", "location": "Conference Room", "model": "Cisco Aironet 2802i"},
    {"device": "Access-Point-C", "ip": "10.0.0.7", "type": "Network", "status": "Maintenance", "location": "Cafeteria", "model": "Ubiquiti UniFi UAP-AC-Pro"},
    {"device": "Firewall-Primary", "ip": "10.0.0.4", "type": "Network", "status": "Online", "location": "Server Room", "model": "Fortinet FortiGate 100F"},
    {"device": "Network-Load-Balancer", "ip": "10.0.0.8", "type": "Network", "status": "Online", "location": "Server Room", "model": "F5 BIG-IP i2600"},
    {"device": "Core-Switch", "ip": "10.0.0.9", "type": "Network", "status": "Online", "location": "Server Room", "model": "Cisco Catalyst 9300"},
    {"device": "Managed-Switch-Lobby", "ip": "10.0.0.10", "type": "Network", "status": "Online", "location": "Lobby", "model": "Netgear GS724T"},
    
    # Workstations
    {"device": "Reception-PC", "ip": "10.0.0.61", "type": "Workstation", "status": "Online", "location": "Reception", "model": "Dell OptiPlex 7090"},
    {"device": "Conference-PC", "ip": "10.0.0.62", "type": "Workstation", "status": "Idle", "location": "Conference Room", "model": "HP ProDesk 600 G6"},
    {"device": "Kiosk-Lobby", "ip": "10.0.0.63", "type": "Workstation", "status": "Online", "location": "Lobby", "model": "Lenovo ThinkCentre M75q"},
    {"device": "Design-Workstation-1", "ip": "10.0.0.64", "type": "Workstation", "status": "Online", "location": "Design Department", "model": "Dell Precision 5820"},
    {"device": "Design-Workstation-2", "ip": "10.0.0.65", "type": "Workstation", "status": "Online", "location": "Design Department", "model": "HP Z4 G4"},
    {"device": "CAD-Workstation", "ip": "10.0.0.66", "type": "Workstation", "status": "Maintenance", "location": "Engineering", "model": "Dell Precision 7920"},
    {"device": "Training-PC-1", "ip": "10.0.0.67", "type": "Workstation", "status": "Offline", "location": "Training Room", "model": "HP ProDesk 400 G7"},
    {"device": "Training-PC-2", "ip": "10.0.0.68", "type": "Workstation", "status": "Online", "location": "Training Room", "model": "HP ProDesk 400 G7"},
    
    # Mobile Devices
    {"device": "Tablet-Sales-01", "ip": "10.0.3.30", "type": "Tablet", "status": "Online", "location": "Sales Department", "model": "iPad Pro 11"},
    {"device": "Tablet-Inventory", "ip": "10.0.3.31", "type": "Tablet", "status": "Online", "location": "Warehouse", "model": "Samsung Galaxy Tab S8"},
    {"device": "Tablet-Sales-02", "ip": "10.0.3.35", "type": "Tablet", "status": "Offline", "location": "Sales Floor", "model": "Microsoft Surface Pro 8"},
    {"device": "Tablet-Presentation", "ip": "10.0.3.36", "type": "Tablet", "status": "Idle", "location": "Conference Room", "model": "iPad Air 5"},
    {"device": "Phone-Manager", "ip": "10.0.3.32", "type": "Phone", "status": "Online", "location": "Manager Office", "model": "iPhone 13 Pro"},
    {"device": "Phone-Security", "ip": "10.0.3.33", "type": "Phone", "status": "Online", "location": "Security Desk", "model": "Samsung Galaxy S22"},
    {"device": "Phone-Reception", "ip": "10.0.3.34", "type": "Phone", "status": "Online", "location": "Reception", "model": "iPhone 12"},
    
    # Additional Equipment
    {"device": "UPS-Server-Room", "ip": "10.0.4.10", "type": "UPS", "status": "Online", "location": "Server Room", "model": "APC Smart-UPS 3000VA"},
    {"device": "UPS-Network-Closet", "ip": "10.0.4.11", "type": "UPS", "status": "Online", "location": "Network Closet", "model": "CyberPower CP1500AVRLCD"},
    {"device": "Scanner-HR", "ip": "10.0.0.80", "type": "Scanner", "status": "Online", "location": "HR Department", "model": "Fujitsu ScanSnap iX1600"},
    {"device": "Scanner-Accounting", "ip": "10.0.0.81", "type": "Scanner", "status": "Idle", "location": "Accounting", "model": "Epson WorkForce ES-500W"},
    {"device": "Projector-Conference", "ip": "10.0.0.90", "type": "Projector", "status": "Online", "location": "Main Conference Room", "model": "Epson PowerLite 2250U"},
    {"device": "Projector-Training", "ip": "10.0.0.91", "type": "Projector", "status": "Maintenance", "location": "Training Room", "model": "BenQ MW632ST"},
    {"device": "NAS-Backup", "ip": "10.0.1.20", "type": "Storage", "status": "Online", "location": "Server Room", "model": "QNAP TS-464C2"},
    {"device": "Video-Conferencing", "ip": "10.0.0.95", "type": "AV Equipment", "status": "Online", "location": "Board Room", "model": "Poly Studio X70"}
]

def get_mock_inventory():
    """Returns the complete inventory list for testing/discovery."""
    return mock_devices

def get_random_device():
    """Returns a single random device from the inventory"""
    return random.choice(mock_devices)

def get_random_devices(count=5):
    """Returns a random sample of devices from the inventory"""
    return random.sample(mock_devices, min(count, len(mock_devices)))

def get_devices_by_type(device_type):
    """Returns all devices of a specific type"""
    return [device for device in mock_devices if device["type"] == device_type]

def get_devices_by_status(status):
    """Returns all devices with a specific status"""
    return [device for device in mock_devices if device["status"] == status]

def get_devices_by_location(location):
    """Returns all devices at a specific location"""
    return [device for device in mock_devices if "location" in device and location.lower() in device["location"].lower()]

def get_online_devices():
    """Returns all online devices"""
    return get_devices_by_status("Online")

def get_offline_devices():
    """Returns all offline devices"""
    return get_devices_by_status("Offline")

def get_maintenance_devices():
    """Returns all devices currently under maintenance"""
    return get_devices_by_status("Maintenance")

def get_device_count():
    """Returns the total number of devices in inventory"""
    return len(mock_devices)

def get_device_count_by_type():
    """Returns a count of devices by type"""
    type_counts = {}
    for device in mock_devices:
        device_type = device["type"]
        type_counts[device_type] = type_counts.get(device_type, 0) + 1
    return type_counts

def get_device_count_by_status():
    """Returns a count of devices by status"""
    status_counts = {}
    for device in mock_devices:
        status = device["status"]
        status_counts[status] = status_counts.get(status, 0) + 1
    return status_counts

def get_device_by_ip(ip_address):
    """Returns a device by its IP address"""
    for device in mock_devices:
        if device["ip"] == ip_address:
            return device
    return None

def get_device_by_name(device_name):
    """Returns a device by its name"""
    for device in mock_devices:
        if device["device"] == device_name:
            return device
    return None

def search_devices(search_term):
    """Search devices by name, type, location, or model"""
    search_term = search_term.lower()
    results = []
    for device in mock_devices:
        if (search_term in device["device"].lower() or
            search_term in device["type"].lower() or
            search_term in device["status"].lower() or
            ("location" in device and search_term in device["location"].lower()) or
            ("model" in device and search_term in device["model"].lower())):
            results.append(device)
    return results

def get_inventory_summary():
    """Returns a summary of the inventory"""
    total_devices = get_device_count()
    online_count = len(get_online_devices())
    offline_count = len(get_offline_devices())
    maintenance_count = len(get_maintenance_devices())
    
    return {
        "total_devices": total_devices,
        "online": online_count,
        "offline": offline_count,
        "maintenance": maintenance_count,
        "device_types": get_device_count_by_type(),
        "status_breakdown": get_device_count_by_status()
    }
