import socket
import struct
import sys
import time
from collections import OrderedDict

# --- Debug Flag ---
# Set to True to print detailed network communication
DEBUG = True

# --- WIZnet Protocol Constants ---
WIZNET_PORT_UDP = 1460
LOCAL_UDP_PORT = 5001
BROADCAST_IP = '255.255.255.255'
DISCOVERY_COMMAND = b'FIND'

CONFIG_PORT_TCP = 1461
CONFIG_COMMAND_SETT = b'SETT'
CONFIG_RESPONSE_SETC = b'SETC'

# --- Human-readable Mappings (using OrderedDict to preserve order) ---
OP_MODES = OrderedDict([(0x00, "Client"), (0x01, "Server"), (0x02, "Mixed")])
BAUD_RATES = OrderedDict([
    (0xA0, "1200"), (0xD0, "2400"), (0xE8, "4800"), (0xF4, "9600"),
    (0xFA, "19200"), (0xFD, "38400"), (0xFE, "57600"), (0xFF, "115200"),
    (0xBB, "230400")
])
DATA_BITS = OrderedDict([(0x07, "7 bits"), (0x08, "8 bits")])
PARITY = OrderedDict([(0x00, "None"), (0x01, "Odd"), (0x02, "Even")])
STOP_BITS = OrderedDict([(0x01, "1 bit")])
FLOW_CONTROL = OrderedDict([(0x00, "None"), (0x01, "Xon/Xoff"), (0x02, "CTS/RTS")])
DHCP_MODES = OrderedDict([(0x00, "Static IP"), (0x01, "DHCP"), (0x02, "PPPoE")])
PROTOCOL = OrderedDict([(0x00, "TCP"), (0x01, "UDP")])
DOMAIN_FLAG = OrderedDict([(0x00, "IP Address"), (0x01, "Domain Name")])
SERIAL_CONFIG_MODE = OrderedDict([(0x00, "Disabled"), (0x01, "Enabled")])
PASSWORD_ENABLED = OrderedDict([(0x00, "Disabled"), (0x01, "Enabled")])


# --- Reverse Mappings for Configuration ---
REVERSE_OP_MODES = {v: k for k, v in OP_MODES.items()}
REVERSE_BAUD_RATES = {v: k for k, v in BAUD_RATES.items()}
REVERSE_DATA_BITS = {v: k for k, v in DATA_BITS.items()}
REVERSE_PARITY = {v: k for k, v in PARITY.items()}
REVERSE_STOP_BITS = {v: k for k, v in STOP_BITS.items()}
REVERSE_FLOW_CONTROL = {v: k for k, v in FLOW_CONTROL.items()}
REVERSE_DHCP_MODES = {v: k for k, v in DHCP_MODES.items()}
REVERSE_PROTOCOL = {v: k for k, v in PROTOCOL.items()}
REVERSE_DOMAIN_FLAG = {v: k for k, v in DOMAIN_FLAG.items()}
REVERSE_SERIAL_CONFIG_MODE = {v: k for k, v in SERIAL_CONFIG_MODE.items()}
REVERSE_PASSWORD_ENABLED = {v: k for k, v in PASSWORD_ENABLED.items()}


def calculate_crc16(data):
    """Calculates a CRC-16 checksum on a byte string using the MODBUS algorithm."""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc >>= 1
                crc ^= 0xA001
            else:
                crc >>= 1
    return crc


def discover_wiznet_devices():
    """
    Sends a UDP broadcast to discover WIZnet devices and returns a list of them,
    parsing the full configuration packet received in the response.
    """
    found_devices = []

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    try:
        sock.bind(('', LOCAL_UDP_PORT))
    except Exception as e:
        if DEBUG:
            print(f"DEBUG: Could not bind to port {LOCAL_UDP_PORT}. This is normal if it's in use.")
            print(f"DEBUG: Error: {e}")

    print("--- STEP 1: Discovering Devices ---")
    if DEBUG:
        print(f"DEBUG: Sending discovery command '{DISCOVERY_COMMAND.decode()}' to {BROADCAST_IP}:{WIZNET_PORT_UDP}")
        print(f"DEBUG: Listening for responses on local port {LOCAL_UDP_PORT}")

    try:
        sock.sendto(DISCOVERY_COMMAND, (BROADCAST_IP, WIZNET_PORT_UDP))

        while True:
            try:
                data, addr = sock.recvfrom(1024)

                if DEBUG:
                    print("-" * 50)
                    print(f"DEBUG: Received packet from {addr}")
                    print(f"DEBUG: Raw Data Length: {len(data)} bytes")
                    print(f"DEBUG: Raw Hexadecimal Data: {data.hex()}")
                    print("-" * 50)

                if len(data) == 163 and data.startswith(b'IMIN'):
                    payload = data[4:]

                    mac_addr = ":".join(f"{b:02x}" for b in payload[0:6]).upper()
                    
                    ip_addr = socket.inet_ntoa(payload[7:11])
                    
                    settings = {
                        "op_mode": OP_MODES.get(payload[6], "Unknown"),
                        "ip": ip_addr,
                        "subnet": socket.inet_ntoa(payload[11:15]),
                        "gateway": socket.inet_ntoa(payload[15:19]),
                        "port": struct.unpack('!H', payload[19:21])[0],
                        "remote_ip": socket.inet_ntoa(payload[21:25]),
                        "remote_port": struct.unpack('!H', payload[25:27])[0],
                        "baud_rate": BAUD_RATES.get(payload[27], "Unknown"),
                        "data_bits": DATA_BITS.get(payload[28], "Unknown"),
                        "parity": PARITY.get(payload[29], "Unknown"),
                        "stop_bits": STOP_BITS.get(payload[30], "Unknown"),
                        "flow_control": FLOW_CONTROL.get(payload[31], "Unknown"),
                        "special_char": f"{payload[32]:#04x}" if payload[32] != 0 else "Disabled",
                        "packet_length": struct.unpack('!H', payload[33:35])[0],
                        "packet_interval": struct.unpack('!H', payload[35:37])[0],
                        "inactivity_timeout": struct.unpack('!H', payload[37:39])[0],
                        "debug_mode": "Enabled" if payload[39] == 0x00 else "Disabled",
                        "version": f"{((struct.unpack('!H', payload[40:42])[0] & 0xFF00) >> 8)}.{ (struct.unpack('!H', payload[40:42])[0] & 0x00FF)}",
                        "dhcp_mode": DHCP_MODES.get(payload[42], "Unknown"),
                        "protocol": PROTOCOL.get(payload[43], "Unknown"),
                        "conn_status": "Connected" if payload[44] == 0x01 else "Disconnected",
                        "domain_flag": DOMAIN_FLAG.get(payload[45], "Unknown"),
                        "dns_ip": socket.inet_ntoa(payload[46:50]),
                        "domain_name": payload[50:82].decode('ascii', errors='replace').strip('\x00'),
                        "serial_cfg_mode": SERIAL_CONFIG_MODE.get(payload[82], "Unknown"),
                        "serial_cfg_string": payload[83:86].decode('ascii', errors='replace').strip('\x00'),
                        "pppoe_id": payload[86:118].decode('ascii', errors='replace').strip('\x00'),
                        "pppoe_password": payload[118:150].decode('ascii', errors='replace').strip('\x00'),
                        "password_enabled": PASSWORD_ENABLED.get(payload[150], "Unknown"),
                        "conn_password": payload[151:159].decode('ascii', errors='replace').strip('\x00'),
                    }
                    
                    device_info = {
                        "ip": ip_addr,
                        "mac": mac_addr,
                        "raw_data": data,
                        "settings": settings,
                        "address": addr,
                    }
                    found_devices.append(device_info)
                    
            except socket.timeout:
                if DEBUG:
                    print("DEBUG: Socket timeout reached. No more packets received.")
                break
            except Exception as e:
                 print(f"An error occurred while parsing: {e}")
                 
    except Exception as e:
        print(f"An error occurred during discovery: {e}")
    finally:
        sock.close()

    return found_devices


def configure_device(device_info, new_settings):
    """
    Sends a full configuration packet to the device to apply new settings.
    """
    print("\n--- STEP 2: Configuring Device ---")
    
    payload_data = bytearray(device_info['raw_data'][4:])
    
    try:
        # --- Update all fields based on user input ---
        # Network settings
        payload_data[6] = REVERSE_OP_MODES[new_settings['op_mode']]
        payload_data[7:11] = socket.inet_aton(new_settings['ip'])
        payload_data[11:15] = socket.inet_aton(new_settings['subnet'])
        payload_data[15:19] = socket.inet_aton(new_settings['gateway'])
        payload_data[19:21] = struct.pack('!H', new_settings['port'])
        payload_data[21:25] = socket.inet_aton(new_settings['remote_ip'])
        payload_data[25:27] = struct.pack('!H', new_settings['remote_port'])
        payload_data[42] = REVERSE_DHCP_MODES[new_settings['dhcp_mode']]
        payload_data[43] = REVERSE_PROTOCOL[new_settings['protocol']]
        payload_data[45] = REVERSE_DOMAIN_FLAG[new_settings['domain_flag']]
        payload_data[46:50] = socket.inet_aton(new_settings['dns_ip'])
        # Use errors='replace' to handle any Unicode characters from the initial decode
        payload_data[50:82] = new_settings['domain_name'].encode('ascii', errors='replace').ljust(32, b'\x00')

        # Serial settings
        payload_data[27] = REVERSE_BAUD_RATES[new_settings['baud_rate']]
        payload_data[28] = REVERSE_DATA_BITS[new_settings['data_bits']]
        payload_data[29] = REVERSE_PARITY[new_settings['parity']]
        payload_data[30] = REVERSE_STOP_BITS[new_settings['stop_bits']]
        payload_data[31] = REVERSE_FLOW_CONTROL[new_settings['flow_control']]
        payload_data[32] = new_settings['special_char_byte']
        
        # Data packing settings
        payload_data[33:35] = struct.pack('!H', new_settings['packet_length'])
        payload_data[35:37] = struct.pack('!H', new_settings['packet_interval'])
        
        # Miscellaneous
        payload_data[37:39] = struct.pack('!H', new_settings['inactivity_timeout'])
        payload_data[39] = 0x01 if new_settings['debug_mode'] == 'Disabled' else 0x00
        payload_data[82] = REVERSE_SERIAL_CONFIG_MODE[new_settings['serial_cfg_mode']]
        # Use errors='replace' to handle any Unicode characters from the initial decode
        payload_data[83:86] = new_settings['serial_cfg_string'].encode('ascii', errors='replace').ljust(3, b'\x00')
        payload_data[86:118] = new_settings['pppoe_id'].encode('ascii', errors='replace').ljust(32, b'\x00')
        payload_data[118:150] = new_settings['pppoe_password'].encode('ascii', errors='replace').ljust(32, b'\x00')
        payload_data[150] = REVERSE_PASSWORD_ENABLED[new_settings['password_enabled']]
        payload_data[151:159] = new_settings['conn_password'].encode('ascii', errors='replace').ljust(8, b'\x00')

        # Recalculate and update the CRC at the end of the payload (last 2 bytes)
        data_for_crc = payload_data[0:157]
        crc_value = calculate_crc16(data_for_crc)
        struct.pack_into('<H', payload_data, 157, crc_value)
        
        # Prepend the SETT command to the final payload
        final_packet = CONFIG_COMMAND_SETT + payload_data
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        
        if DEBUG:
            print(f"DEBUG: Attempting TCP connection to {device_info['ip']}:{CONFIG_PORT_TCP}")

        sock.connect((device_info['ip'], CONFIG_PORT_TCP))
        
        if DEBUG:
            print(f"DEBUG: Connection successful. Sending new config packet.")
            print(f"DEBUG: New config packet hex: {final_packet.hex()}")

        sock.sendall(final_packet)

        response_data = sock.recv(163) # Expecting SETC + 159 bytes
        
        if DEBUG:
            print("-" * 50)
            print(f"DEBUG: Received response from device.")
            print(f"DEBUG: Raw Data Length: {len(response_data)} bytes")
            print(f"DEBUG: Raw Hexadecimal Data: {response_data.hex()}")
            print("-" * 50)
        
        if response_data.startswith(CONFIG_RESPONSE_SETC):
            print("Configuration command sent and acknowledged successfully.")
            return True
        else:
            print("Configuration failed: Device did not send a valid SETC response.")
            return False
        
    except socket.timeout:
        print("Error: Connection timed out.")
        return False
    except Exception as e:
        print(f"An error occurred during configuration: {e}")
        return False
    finally:
        if 'sock' in locals():
            sock.close()
    return True


def get_user_input(prompt, current_value, options=None, is_int=False, is_ip=False):
    while True:
        try:
            if options:
                option_values = list(options.values())
                print(f"   Current: {current_value}")
                for i, option in enumerate(option_values):
                    print(f"     [{i+1}] {option}")
                user_input = input(f"   New {prompt} (Enter #): ")
                if not user_input:
                    return current_value
                
                choice = int(user_input)
                if 1 <= choice <= len(option_values):
                    return option_values[choice - 1]
                else:
                    print("Invalid option. Please choose a number from the list.")
            else:
                print(f"   Current: {current_value}")
                user_input = input(f"   New {prompt}: ")
                if not user_input:
                    return current_value
                
                if is_int:
                    return int(user_input)
                elif is_ip:
                    socket.inet_aton(user_input)
                    return user_input
                else:
                    return user_input
        except (ValueError, OSError):
            print("Invalid input. Please try again.")

def main():
    """
    Main execution of the discovery and configuration utility.
    """
    print("--- WIZnet Device Configuration Utility ---")
    
    devices = discover_wiznet_devices()

    if not devices:
        print("\nNo WIZnet devices were found on the network.")
        sys.exit(1)

    print("\n--- Found WIZnet Devices ---")
    for i, dev in enumerate(devices):
        settings = dev['settings']
        print("-" * 30)
        print(f"[{i+1}] Device at {dev['ip']}")
        print(f"   MAC Address: {dev['mac']}")
        print(f"   Firmware Version: {settings['version']}")
        print("\n   --- Network Settings ---")
        print(f"     Mode: {settings['op_mode']}")
        print(f"     IP Address: {settings['ip']} ({settings['dhcp_mode']})")
        print(f"     Subnet Mask: {settings['subnet']}")
        print(f"     Gateway: {settings['gateway']}")
        print(f"     Local Port: {settings['port']}")
        print(f"     Protocol: {settings['protocol']}")
        print(f"     DNS Server: {settings['dns_ip']}")
        print("\n   --- Remote Host Settings ---")
        print(f"     Remote IP: {settings['remote_ip']}")
        print(f"     Remote Port: {settings['remote_port']}")
        print(f"     Remote Host Type: {settings['domain_flag']}")
        if settings['domain_name']:
            print(f"     Domain Name: {settings['domain_name']}")
        print(f"     Connection Status: {settings['conn_status']}")
        print("\n   --- Serial Settings ---")
        print(f"     Baud Rate: {settings['baud_rate']}")
        print(f"     Data Bits: {settings['data_bits']}")
        print(f"     Parity: {settings['parity']}")
        print(f"     Stop Bits: {settings['stop_bits']}")
        print(f"     Flow Control: {settings['flow_control']}")
        print("\n   --- Data Packing Settings ---")
        print(f"     Packing Character: {settings['special_char']}")
        print(f"     Packing Length: {settings['packet_length']}")
        print(f"     Packing Interval: {settings['packet_interval']} ms")
        print("\n   --- Miscellaneous ---")
        print(f"     Inactivity Timeout: {settings['inactivity_timeout']} s")
        print(f"     Debug Messages: {settings['debug_mode']}")
        print(f"     Serial Config Mode: {settings['serial_cfg_mode']}")
        if settings['serial_cfg_string']:
             print(f"     Serial Config String: {settings['serial_cfg_string']}")
        print(f"     Connection Password Enabled: {settings['password_enabled']}")
        if settings['conn_password']:
            print(f"     Connection Password: {settings['conn_password']}")
    print("-" * 30)

    try:
        choice = int(input("\nEnter the number of the device to configure: "))
        if not 1 <= choice <= len(devices):
            raise ValueError
        
        selected_device = devices[choice - 1]
        settings = selected_device['settings']
        print(f"Selected device: {selected_device['mac']} at {selected_device['ip']}")

        new_settings = settings.copy()

        print("\n--- Enter New Configuration (press Enter to keep current value) ---")
        print("\n--- Network Settings ---")
        new_settings['dhcp_mode'] = get_user_input("DHCP Mode", settings['dhcp_mode'], DHCP_MODES)
        new_settings['op_mode'] = get_user_input("Operation Mode", settings['op_mode'], OP_MODES)
        new_settings['protocol'] = get_user_input("Protocol", settings['protocol'], PROTOCOL)
        new_settings['ip'] = get_user_input("IP Address", settings['ip'], is_ip=True)
        new_settings['subnet'] = get_user_input("Subnet Mask", settings['subnet'], is_ip=True)
        new_settings['gateway'] = get_user_input("Gateway", settings['gateway'], is_ip=True)
        new_settings['port'] = get_user_input("Local Port", settings['port'], is_int=True)
        new_settings['dns_ip'] = get_user_input("DNS Server IP", settings['dns_ip'], is_ip=True)
        new_settings['domain_flag'] = get_user_input("Remote Host Type", settings['domain_flag'], DOMAIN_FLAG)
        new_settings['remote_ip'] = get_user_input("Remote Host IP", settings['remote_ip'], is_ip=True)
        new_settings['remote_port'] = get_user_input("Remote Host Port", settings['remote_port'], is_int=True)
        new_settings['domain_name'] = get_user_input("Remote Host Domain Name", settings['domain_name'])

        print("\n--- Serial Settings ---")
        new_settings['baud_rate'] = get_user_input("Baud Rate", settings['baud_rate'], BAUD_RATES)
        new_settings['data_bits'] = get_user_input("Data Bits", settings['data_bits'], DATA_BITS)
        new_settings['parity'] = get_user_input("Parity", settings['parity'], PARITY)
        new_settings['flow_control'] = get_user_input("Flow Control", settings['flow_control'], FLOW_CONTROL)
        
        print("\n--- Data Packing Settings ---")
        new_special_char = get_user_input("Packing Character (hex, e.g., 0x0d)", settings['special_char'])
        try:
            new_settings['special_char_byte'] = int(new_special_char, 16)
        except ValueError:
            new_settings['special_char_byte'] = 0 if new_special_char == 'Disabled' else int(settings['special_char'], 16)

        new_settings['packet_length'] = get_user_input("Packing Length", settings['packet_length'], is_int=True)
        new_settings['packet_interval'] = get_user_input("Packing Interval (ms)", settings['packet_interval'], is_int=True)
        
        print("\n--- Miscellaneous Settings ---")
        new_settings['inactivity_timeout'] = get_user_input("Inactivity Timeout (s)", settings['inactivity_timeout'], is_int=True)
        new_settings['debug_mode'] = get_user_input("Debug Messages", settings['debug_mode'], {"Enabled": "Enabled", "Disabled": "Disabled"})
        new_settings['serial_cfg_mode'] = get_user_input("Serial Config Mode", settings['serial_cfg_mode'], SERIAL_CONFIG_MODE)
        new_settings['serial_cfg_string'] = get_user_input("Serial Config String", settings['serial_cfg_string'])
        new_settings['password_enabled'] = get_user_input("Connection Password Enabled", settings['password_enabled'], PASSWORD_ENABLED)
        new_settings['conn_password'] = get_user_input("Connection Password", settings['conn_password'])
        
        if configure_device(selected_device, new_settings):
            print("\nConfiguration command sent.")
        else:
            print("\nFailed to configure device.")
            
    except (ValueError, IndexError):
        print("Invalid choice. Please enter a valid number from the list.")
        sys.exit(1)


if __name__ == "__main__":
    main()
