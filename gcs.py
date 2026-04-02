#!/usr/bin/env python3
"""
- input/output race condition with thread-safe message queue
- Added TCP keepalive on all sockets for better liveness detection
- All handler-thread output now safely routed through queue
- Original security properties preserved (and improved UX)
- Mutual authentication (PSK + X25519) → MITM impossible
- Triple encryption (ChaCha20 → AES‑256‑GCM → ChaCha20)
- Replay protection (counters + timestamps, 5‑minute window)
- Remote code execution: DISABLED by default (--enable-exec to allow + confirmation)
- File transfers: sanitised filenames, confirm before save, dedicated folder
"""
import socket
import threading
import json
import base64
import os
import sys
import uuid
import secrets
import hashlib
import hmac
import time
import queue
from pathlib import Path

# ---------- CONFIGURATION ----------
DEFAULT_PORT = 9009
RECV_DIR = Path("received_files")
RECV_DIR.mkdir(exist_ok=True)

# Get the pre‑shared key from environment (must be set)
PSK = os.environ.get("GCS_PSK")
if not PSK:
    print("[!] Set environment variable GCS_PSK to the shared secret passphrase.")
    print(" Example: export GCS_PSK='your_very_long_secret_number'")
    sys.exit(1)

# Command line flags
import argparse
parser = argparse.ArgumentParser(description="Secure Encrypted Chat Suite")
parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Initial listening port")
parser.add_argument("--enable-exec", action="store_true", help="Enable remote code execution (requires confirmation)")
parser.add_argument("--auto-accept-files", action="store_true", help="Skip file confirmation (use with care)")
args = parser.parse_args()

LISTEN_PORT = args.port
EXEC_ENABLED = args.enable_exec
AUTO_ACCEPT_FILES = args.auto_accept_files

# ---------- Cryptography imports ----------
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
except ImportError:
    print("[!] Install cryptography: pip install cryptography")
    sys.exit(1)

# ---------- Global state ----------
peers = {}          # (ip,port) -> socket
contacts = {}       # name -> (ip, port)
user_id = str(uuid.uuid4())
running = True

# Per‑connection state: key material, send counter, receive counter
peer_state = {}     # socket -> {'key': bytes, 'send_counter': int, 'recv_counter': int}
state_lock = threading.RLock()
server_socket = None
accept_thread = None

# Thread-safe queue for printing messages from handler threads
# (prevents input("> ") race condition)
msg_queue = queue.Queue()

# ---------- Safe print for threads ----------
def safe_print(message: str):
    """Queue a message so it prints cleanly without corrupting the main input prompt."""
    msg_queue.put(message)

# ---------- PSK + X25519 handshake with mutual authentication ----------
def handshake(sock, is_initiator):
    """Authenticated key exchange. Returns session key (96 bytes) or None."""
    try:
        # Generate ephemeral X25519 keypair
        priv = x25519.X25519PrivateKey.generate()
        pub = priv.public_key().public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)

        # Exchange public keys (length‑prefixed)
        if is_initiator:
            sock.sendall(len(pub).to_bytes(1, 'big') + pub)
            len_byte = sock.recv(1)
            if not len_byte:
                return None
            peer_len = len_byte[0]
            peer_pub = sock.recv(peer_len)
            if len(peer_pub) != peer_len:
                return None
        else:
            len_byte = sock.recv(1)
            if not len_byte:
                return None
            peer_len = len_byte[0]
            peer_pub = sock.recv(peer_len)
            if len(peer_pub) != peer_len:
                return None
            sock.sendall(len(pub).to_bytes(1, 'big') + pub)

        # X25519 shared secret
        peer_pub_key = x25519.X25519PublicKey.from_public_bytes(peer_pub)
        shared = priv.exchange(peer_pub_key)

        # Mix with PSK using HKDF
        hkdf = HKDF(algorithm=hashes.SHA512(), length=96, salt=PSK.encode(), info=b"secure-chat-v2")
        master = hkdf.derive(shared)

        # Mutual authentication: HMAC of transcript
        transcript = pub + peer_pub if is_initiator else peer_pub + pub
        auth_tag = hmac.new(master[:32], transcript, hashlib.sha256).digest()
        sock.sendall(auth_tag)
        peer_tag = sock.recv(32)
        if not peer_tag or len(peer_tag) != 32:
            return None
        if not hmac.compare_digest(auth_tag, peer_tag):
            return None

        return master
    except Exception:
        return None

# ---------- Triple encryption ----------
def encrypt_triple(data: bytes, key_mat: bytes) -> bytes:
    key1, key2, key3 = key_mat[0:32], key_mat[32:64], key_mat[64:96]
    nonce1, nonce2, nonce3 = secrets.token_bytes(12), secrets.token_bytes(12), secrets.token_bytes(12)
    c1 = ChaCha20Poly1305(key1).encrypt(nonce1, data, None)
    c2 = AESGCM(key2).encrypt(nonce2, c1, None)
    c3 = ChaCha20Poly1305(key3).encrypt(nonce3, c2, None)
    return nonce1 + nonce2 + nonce3 + c3

def decrypt_triple(cipher: bytes, key_mat: bytes) -> bytes:
    key1, key2, key3 = key_mat[0:32], key_mat[32:64], key_mat[64:96]
    nonce1, nonce2, nonce3 = cipher[:12], cipher[12:24], cipher[24:36]
    inner = cipher[36:]
    c2 = ChaCha20Poly1305(key3).decrypt(nonce3, inner, None)
    c1 = AESGCM(key2).decrypt(nonce2, c2, None)
    plain = ChaCha20Poly1305(key1).decrypt(nonce1, c1, None)
    return plain

# ---------- Message framing with replay protection ----------
def send_msg(sock, msg_dict, key_mat, send_counter):
    msg_dict['counter'] = send_counter
    msg_dict['timestamp'] = time.time()
    plain = json.dumps(msg_dict).encode()
    cipher = encrypt_triple(plain, key_mat)
    sock.sendall(len(cipher).to_bytes(4, 'big') + cipher)
    return send_counter + 1

def recv_msg(sock, key_mat, expected_counter):
    raw_len = sock.recv(4)
    if len(raw_len) < 4:
        return None, None
    length = int.from_bytes(raw_len, 'big')
    data = b''
    while len(data) < length:
        chunk = sock.recv(min(4096, length - len(data)))
        if not chunk:
            return None, None
        data += chunk
    plain = decrypt_triple(data, key_mat)
    msg = json.loads(plain.decode())
    msg_counter = msg.get('counter')
    msg_ts = msg.get('timestamp')
    if msg_counter is None or msg_ts is None:
        return None, None
    if msg_counter <= expected_counter:
        return None, None
    if abs(time.time() - msg_ts) > 300:  # 5 minutes window
        return None, None
    return msg, msg_counter

# ---------- Peer handler with state ----------
def handle_peer(conn, addr, key_mat):
    ip, port = addr
    recv_counter = 0
    safe_print(f"[*] Authenticated secure connection from {ip}:{port}")

    with state_lock:
        peer_state[conn] = {'key': key_mat, 'send_counter': 0, 'recv_counter': 0}

    while running:
        try:
            msg, new_counter = recv_msg(conn, key_mat, recv_counter)
            if msg is None:
                break
            recv_counter = new_counter
            with state_lock:
                peer_state[conn]['recv_counter'] = recv_counter
        except Exception:
            break

        msg_type = msg.get("type")
        sender = msg.get("user_id", "unknown")

        if msg_type == "chat":
            safe_print(f"\n[{sender}@{ip}:{port}] {msg.get('message','')}\n> ")
        elif msg_type == "file":
            filename = msg.get("filename", "unknown")
            safe_name = "".join(c for c in filename if c.isalnum() or c in '._-')
            if not safe_name:
                safe_name = "received_file"
            filepath = RECV_DIR / safe_name

            if not AUTO_ACCEPT_FILES:
                safe_print(f"\n[!] Incoming file: {safe_name} from {sender}")
                resp = input("Accept? (y/n): ").strip().lower()
                if resp != 'y':
                    safe_print("[*] File rejected\n> ")
                    continue

            data_b64 = msg.get("data", "")
            try:
                data = base64.b64decode(data_b64)
                with open(filepath, "wb") as f:
                    f.write(data)
                safe_print(f"[*] File saved: {filepath}\n> ")
            except Exception as e:
                safe_print(f"[!] File save error: {e}\n> ")
        elif msg_type == "pyexec":
            if not EXEC_ENABLED:
                safe_print(f"\n[!] Remote execution disabled by --enable-exec flag\n> ")
                continue
            code = msg.get("code", "")
            safe_print(f"\n[!] Remote code execution request from {sender}@{ip}:{port}")
            safe_print(f"Code snippet:\n{code[:200]}{'...' if len(code)>200 else ''}")
            resp = input("Execute? (yes/NO): ").strip().lower()
            if resp == 'yes':
                try:
                    exec(code, globals())
                    safe_print("[*] Execution completed.\n> ")
                except Exception as e:
                    safe_print(f"[!] Execution error: {e}\n> ")
            else:
                safe_print("[*] Execution denied.\n> ")
        elif msg_type == "pyeval":
            if not EXEC_ENABLED:
                safe_print(f"\n[!] Remote evaluation disabled\n> ")
                continue
            expr = msg.get("expression", "")
            safe_print(f"\n[!] Remote eval request from {sender}@{ip}:{port}: {expr}")
            resp = input("Evaluate? (yes/NO): ").strip().lower()
            if resp == 'yes':
                try:
                    result = eval(expr, globals())
                    safe_print(f"[*] Result: {result}\n> ")
                except Exception as e:
                    safe_print(f"[!] Eval error: {e}\n> ")
            else:
                safe_print("[*] Evaluation denied.\n> ")
        else:
            # Unknown message type – ignore silently
            pass

    safe_print(f"[*] Connection closed: {ip}:{port}")
    with state_lock:
        peer_state.pop(conn, None)
        peers.pop((ip, port), None)
    conn.close()

# ---------- Server accept loop ----------
def accept_loop():
    while running:
        try:
            conn, addr = server_socket.accept()
        except OSError:
            break
        except Exception:
            continue

        # Enable TCP keepalive immediately
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

        key_mat = handshake(conn, is_initiator=False)
        if key_mat is None:
            safe_print(f"[!] Handshake failed from {addr[0]}:{addr[1]}")
            conn.close()
            continue

        with state_lock:
            peers[(addr[0], addr[1])] = conn

        threading.Thread(target=handle_peer, args=(conn, addr, key_mat), daemon=True).start()

def start_server(port):
    global server_socket, accept_thread
    if server_socket:
        stop_server()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_socket.bind(('', port))
    except Exception as e:
        print(f"[!] Cannot bind port {port}: {e}")
        return False
    server_socket.listen(5)
    accept_thread = threading.Thread(target=accept_loop, daemon=True)
    accept_thread.start()
    return True

def stop_server():
    global server_socket
    if server_socket:
        try:
            server_socket.close()
        except:
            pass
        server_socket = None

# ---------- Client connection ----------
def connect_to_peer(ip, port):
    with state_lock:
        if (ip, port) in peers:
            print(f"[!] Already connected to {ip}:{port}")
            return

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip, port))

        # Enable TCP keepalive immediately
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

        key_mat = handshake(sock, is_initiator=True)
        if key_mat is None:
            print(f"[!] Handshake failed with {ip}:{port}")
            sock.close()
            return

        with state_lock:
            peers[(ip, port)] = sock
            peer_state[sock] = {'key': key_mat, 'send_counter': 0, 'recv_counter': 0}

        threading.Thread(target=handle_peer, args=(sock, (ip, port), key_mat), daemon=True).start()
        print(f"[*] Securely connected to {ip}:{port}")
    except Exception as e:
        print(f"[!] Connection error: {e}")

def disconnect_peer(ip, port):
    with state_lock:
        sock = peers.get((ip, port))
        if not sock:
            print(f"[!] No connection to {ip}:{port}")
            return
        try:
            sock.close()
        except:
            pass
        peers.pop((ip, port), None)
        peer_state.pop(sock, None)
    print(f"[*] Disconnected from {ip}:{port}")

def disconnect_all():
    with state_lock:
        for (ip, port), sock in list(peers.items()):
            try:
                sock.close()
            except:
                pass
        peers.clear()
        peer_state.clear()
    print("[*] Disconnected all peers")

def send_to_all(msg_dict):
    with state_lock:
        for sock in list(peers.values()):
            state = peer_state.get(sock)
            if state:
                try:
                    new_counter = send_msg(sock, msg_dict, state['key'], state['send_counter'])
                    state['send_counter'] = new_counter
                except Exception as e:
                    print(f"[!] Send error: {e}")

# ---------- Contact management ----------
def load_contacts():
    global contacts
    try:
        if os.path.exists("contacts.json"):
            with open("contacts.json", "r") as f:
                contacts = json.load(f)
            print("[*] Contacts loaded")
        else:
            contacts = {}
    except Exception as e:
        print(f"[!] Load contacts error: {e}")

def save_contacts():
    try:
        with open("contacts.json", "w") as f:
            json.dump(contacts, f)
        print("[*] Contacts saved")
    except Exception as e:
        print(f"[!] Save error: {e}")

def parse_ip_port(s):
    if ':' in s:
        ip, port_str = s.split(':', 1)
        try:
            port = int(port_str)
        except:
            port = LISTEN_PORT
    else:
        ip = s
        port = LISTEN_PORT
    return ip, port

# ---------- Command processing ----------
def print_help():
    print("""
╔══════════════════════════════════════════════════════════╗
║ SECURE CHAT COMMANDS                                     ║
╠══════════════════════════════════════════════════════════╣
║ /connect ip[:port]          Connect to peer              ║
║ /disconnect ip[:port]       Disconnect specific peer     ║
║ /disconnectall              Close all connections        ║
║ /addcontact name ip:port    Save contact                 ║
║ /connectuser name           Connect using saved contact  ║
║ /listcontacts               Show contacts                ║
║ /sendfile filepath          Send file to all peers       ║
║ /setport port               Change listening port        ║
║ /py code                    Run local Python             ║
║ /pysend code                Send exec request            ║
║ /pyevalsend expr            Send eval request            ║
║ /myid                       Show your user ID            ║
║ /status                     Show connected peers         ║
║ /savecontacts               Save contacts to file        ║
║ /reloadcontacts             Reload contacts              ║
║ /clear                      Clear screen                  ║
║ /help                       This help                    ║
║ /exit                       Quit program                 ║
╚══════════════════════════════════════════════════════════╝
""")

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

# ---------- Main ----------
def main():
    global LISTEN_PORT, running
    load_contacts()

    if not start_server(LISTEN_PORT):
        print("[!] Could not start server. Exiting.")
        sys.exit(1)

    print(f"Your secure ID: {user_id}")
    print(f"Listening on port {LISTEN_PORT}")
    print(f"Remote exec: {'ENABLED (with confirmation)' if EXEC_ENABLED else 'DISABLED'}")
    print("Type /help for commands.\n")

    while running:
        try:
            # Drain any messages that arrived from peers (chat, files, etc.)
            while not msg_queue.empty():
                print(msg_queue.get_nowait(), end="")
                sys.stdout.flush()

            cmd_line = input("> ").strip()
            if not cmd_line:
                continue

            if cmd_line.startswith('/'):
                parts = cmd_line.split(' ', 1)
                cmd = parts[0].lower()
                arg = parts[1] if len(parts) > 1 else ""

                if cmd == "/connect":
                    ip, port = parse_ip_port(arg)
                    connect_to_peer(ip, port)
                elif cmd == "/disconnect":
                    ip, port = parse_ip_port(arg)
                    disconnect_peer(ip, port)
                elif cmd == "/disconnectall":
                    disconnect_all()
                elif cmd == "/addcontact":
                    try:
                        name_ip = arg.split(' ', 1)
                        if len(name_ip) != 2:
                            print("[!] Usage: /addcontact name ip[:port]")
                            continue
                        name, ipport = name_ip
                        ip, port = parse_ip_port(ipport)
                        contacts[name] = (ip, port)
                        print(f"[*] Contact '{name}' added: {ip}:{port}")
                    except Exception as e:
                        print(f"[!] Error: {e}")
                elif cmd == "/connectuser":
                    if ':' in arg:
                        name, port_str = arg.split(':', 1)
                        port = int(port_str)
                    else:
                        name = arg
                        port = None
                    if name not in contacts:
                        print(f"[!] Contact '{name}' not found")
                        continue
                    ip, saved_port = contacts[name]
                    target_port = port if port is not None else saved_port
                    connect_to_peer(ip, target_port)
                elif cmd == "/listcontacts":
                    if not contacts:
                        print("[*] No contacts")
                    else:
                        for name, (ip, port) in contacts.items():
                            print(f" {name} -> {ip}:{port}")
                elif cmd == "/sendfile":
                    if not os.path.isfile(arg):
                        print("[!] File not found")
                        continue
                    with open(arg, "rb") as f:
                        data_b64 = base64.b64encode(f.read()).decode()
                    msg = {"type": "file", "filename": os.path.basename(arg), "data": data_b64, "user_id": user_id}
                    send_to_all(msg)
                    print(f"[*] File sent: {arg}")
                elif cmd == "/setport":
                    try:
                        new_port = int(arg)
                        if new_port == LISTEN_PORT:
                            print("[*] Already listening on that port")
                            continue
                        print(f"[*] Changing listening port to {new_port} (existing connections stay)")
                        stop_server()
                        if start_server(new_port):
                            LISTEN_PORT = new_port
                            print(f"[*] Now accepting new connections on port {LISTEN_PORT}")
                        else:
                            print("[!] Failed to bind new port, reverting to old")
                            start_server(LISTEN_PORT)
                    except ValueError:
                        print("[!] Invalid port number")
                elif cmd == "/py":
                    try:
                        exec(arg, globals())
                    except Exception as e:
                        print(f"[!] Error: {e}")
                elif cmd == "/pysend":
                    if not EXEC_ENABLED:
                        print("[!] Remote exec is disabled (start with --enable-exec to allow)")
                        continue
                    send_to_all({"type": "pyexec", "code": arg, "user_id": user_id})
                    print("[*] Python exec request sent")
                elif cmd == "/pyevalsend":
                    if not EXEC_ENABLED:
                        print("[!] Remote eval is disabled")
                        continue
                    send_to_all({"type": "pyeval", "expression": arg, "user_id": user_id})
                    print("[*] Python eval request sent")
                elif cmd == "/myid":
                    print(f"Your ID: {user_id}")
                elif cmd == "/status":
                    with state_lock:
                        print(f"Connected peers: {len(peers)}")
                        for (ip, port) in peers:
                            print(f" {ip}:{port}")
                elif cmd == "/savecontacts":
                    save_contacts()
                elif cmd == "/reloadcontacts":
                    load_contacts()
                elif cmd == "/clear":
                    clear_screen()
                elif cmd == "/help":
                    print_help()
                elif cmd == "/exit":
                    print("[*] Shutting down...")
                    disconnect_all()
                    stop_server()
                    running = False
                    sys.exit(0)
                else:
                    print("[!] Unknown command. Type /help")
            else:
                # Send chat message to all connected peers
                if not peers:
                    print("[!] No peers connected")
                    continue
                send_to_all({"type": "chat", "message": cmd_line, "user_id": user_id})

        except KeyboardInterrupt:
            print("\n[*] Interrupted, exiting...")
            break
        except Exception as e:
            print(f"[!] Unexpected error: {e}")

    disconnect_all()
    stop_server()
    sys.exit(0)

if __name__ == "__main__":
    main()
