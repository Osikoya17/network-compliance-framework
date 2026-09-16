from netmiko import ConnectHandler

device = {
    'device_type': 'cisco_ios',
    'host': '192.168.10.1',
    'username': 'ola',
    'password': 'Admin123!',
}

conn = ConnectHandler(**device)
output = conn.send_command('show version')
print(output)
conn.disconnect()
