# START OF ADVANCED CHAT SERVER

import socket
import threading
import sqlite3
import bcrypt

SERVER_IP = "0.0.0.0"
SERVER_PORT = 12345

conn = sqlite3.connect("chat_server.db", check_same_thread=False)
cur = conn.cursor()

# Reset previous data
cur.execute("DROP TABLE IF EXISTS users")
cur.execute("DROP TABLE IF EXISTS contacts")
cur.execute("DROP TABLE IF EXISTS messages")

cur.execute('''
CREATE TABLE users (
    username TEXT PRIMARY KEY,
    password_hash TEXT
)
''')
cur.execute('''
CREATE TABLE contacts (
    username TEXT,
    ip TEXT,
    online INTEGER
)
''')
cur.execute('''
CREATE TABLE messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    to_user TEXT,
    from_user TEXT,
    message TEXT,
    delivered INTEGER DEFAULT 0
)
''')
conn.commit()

clients = {}  # username -> list of sockets
client_lock = threading.Lock()

def broadcast_contact_list():
    cur.execute("SELECT username, online FROM contacts")
    data = cur.fetchall()
    packet = "CONTACT_LIST|" + "::".join([f"{u},{'1' if o else '0'}" for u, o in data])
    with client_lock:
        for user_socks in clients.values():
            for sock in user_socks:
                try:
                    sock.sendall(packet.encode())
                except:
                    pass

def handle_client(sock, addr):
    username = None
    try:
        sock.sendall(b"LOGIN_OR_REGISTER?")
        mode = sock.recv(1024).decode()

        sock.sendall(b"USERNAME?")
        username = sock.recv(1024).decode()

        sock.sendall(b"PASSWORD?")
        password = sock.recv(1024).decode().encode()

        if mode == "register":
            cur.execute("SELECT * FROM users WHERE username=?", (username,))
            if cur.fetchone():
                sock.sendall(b"ERROR|Username already exists.")
                sock.close()
                return
            hash_pw = bcrypt.hashpw(password, bcrypt.gensalt())
            cur.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hash_pw))
            conn.commit()
            sock.sendall(b"REGISTERED")

        elif mode == "login":
            cur.execute("SELECT password_hash FROM users WHERE username=?", (username,))
            row = cur.fetchone()
            if not row or not bcrypt.checkpw(password, row[0]):
                sock.sendall(b"ERROR|Invalid credentials.")
                sock.close()
                return
            sock.sendall(b"LOGGED_IN")

        with client_lock:
            clients.setdefault(username, []).append(sock)
        cur.execute("INSERT OR REPLACE INTO contacts (username, ip, online) VALUES (?, ?, 1)", (username, addr[0]))
        conn.commit()
        broadcast_contact_list()

        # Deliver offline messages
        cur.execute("SELECT from_user, message FROM messages WHERE to_user=? AND delivered=0", (username,))
        for sender, msg in cur.fetchall():
            sock.sendall(f"[Offline from {sender}]: {msg}\n".encode())
        cur.execute("UPDATE messages SET delivered=1 WHERE to_user=?", (username,))
        conn.commit()

        while True:
            data = sock.recv(4096)
            if not data:
                break
            decoded = data.decode()
            if decoded.startswith("LOGOUT_ALL"):
                with client_lock:
                    for s in clients.get(username, []):
                        if s != sock:
                            try:
                                s.send(b"FORCED_LOGOUT")
                                s.close()
                            except:
                                pass
                    clients[username] = [sock]
                continue
            if decoded.startswith("MSG|"):
                _, to_user, msg = decoded.split("|", 2)
                with client_lock:
                    if to_user in clients:
                        for target_sock in clients[to_user]:
                            target_sock.sendall(f"[{username}]: {msg}\n".encode())
                    else:
                        cur.execute("INSERT INTO messages (to_user, from_user, message) VALUES (?, ?, ?)",
                                    (to_user, username, msg))
                        conn.commit()
    except Exception as e:
        print("Error:", e)
    finally:
        if username:
            with client_lock:
                if username in clients:
                    clients[username] = [s for s in clients[username] if s != sock]
                    if not clients[username]:
                        del clients[username]
            cur.execute("UPDATE contacts SET online=0 WHERE username=?", (username,))
            conn.commit()
            broadcast_contact_list()
        sock.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((SERVER_IP, SERVER_PORT))
    server.listen(5)
    print(f"Server running on {SERVER_IP}:{SERVER_PORT}")

    while True:
        client_sock, client_addr = server.accept()
        threading.Thread(target=handle_client, args=(client_sock, client_addr), daemon=True).start()

if __name__ == "__main__":
    start_server()

# END OF ADVANCED CHAT SERVER
