from netmiko import ConnectHandler

device = {
    'device_type': 'cisco_ios',
    'host': '192.168.10.2',
    'username': 'ola',
    'password': 'Admin123!',
    'session_log': 'netmiko_session.log',
}

conn = ConnectHandler(**device)
print("Connected. Base prompt:", conn.base_prompt)
conn.disconnect()
