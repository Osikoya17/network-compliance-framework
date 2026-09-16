from netmiko import ConnectHandler

devices = [
    {'device_type': 'cisco_ios', 'host': '192.168.10.2', 'username': 'ola', 'password': 'Admin123!', 'read_timeout_override': 30},
    {'device_type': 'cisco_ios', 'host': '192.168.10.3', 'username': 'ola', 'password': 'Admin123!', 'read_timeout_override': 30},
]

for device in devices:
    print(f"\n=== Connecting to {device['host']} ===")
    conn = ConnectHandler(**{k: v for k, v in device.items() if k != 'read_timeout_override'})
    output = conn.send_command('show run | include hostname', read_timeout=30)
    print(output)
    conn.disconnect()
