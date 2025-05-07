import logging
import socket
import threading
import json
import psycopg2
import sys
import hashlib

TRACKER_ID = "simple_tracker_v1"

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Establish a connection to the PostgreSQL database
conn = psycopg2.connect(dbname="postgres", user="postgres", password="khoa1906", host="localhost", port="5432")
cur = conn.cursor()

def log_event(message):
    logging.info(message)

def generate_magnet_link(file_name):
    # Create a unique identifier (hash) for the file
    file_hash = hashlib.sha1(file_name.encode()).hexdigest()
    magnet_link = f"magnet:?xt=urn:btih:{file_hash}&dn={file_name}"
    return magnet_link

# Update the client's file list in the database
def update_client_info(peers_ip, peers_port, peers_hostname, file_name, file_size, piece_hash, piece_size, num_order_in_file):
    try:
        for i in range(len(num_order_in_file)):
            cur.execute(
                "INSERT INTO peers (peers_ip, peers_port, peers_hostname, file_name, file_size, piece_hash, piece_size, num_order_in_file) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT (peers_ip, file_name, num_order_in_file) DO NOTHING",
                (peers_ip, peers_port, peers_hostname, file_name, file_size, piece_hash[i], piece_size, num_order_in_file[i])
            )
        conn.commit()
    except Exception as e:
        logging.exception(f"Error updating client info: {e}")

active_connections = {}
host_files = {}

# Handles client commands
def client_handler(conn, addr):
    client_peers_hostname = None
    try:
        while True:
            data = conn.recv(4096).decode('utf-8')
            if not data:
                break

            command = json.loads(data)
            action = command.get("action")

            # Extract client information
            peers_ip = addr[0]
            peers_port = command.get('peers_port')
            client_peers_hostname = command.get('peers_hostname')

            if not peers_port or not client_peers_hostname:
                conn.sendall(json.dumps({"error": "Missing required fields"}).encode('utf-8'))
                continue

            # Handle each action accordingly
            if action == 'introduce':
                active_connections[client_peers_hostname] = conn
                log_event(f"Connected to {client_peers_hostname}/{peers_ip}:{peers_port}")

            elif action == 'publish':
                if all(k in command for k in ('file_name', 'file_size', 'piece_hash', 'piece_size', 'num_order_in_file')):
                    log_event(f"Updating file info in database for {client_peers_hostname}")
                    update_client_info(peers_ip, peers_port, client_peers_hostname,
                                       command['file_name'], command['file_size'],
                                       command['piece_hash'], command['piece_size'],
                                       command['num_order_in_file'])
                    log_event(f"Database update complete for hostname: {client_peers_hostname}/{peers_ip}:{peers_port}")
                    magnet_link = generate_magnet_link(command['file_name'])
                    conn.sendall(json.dumps({"message": "File list updated successfully.", "magnet_link": magnet_link}).encode('utf-8'))
                else:
                    conn.sendall(json.dumps({"error": "Incomplete publish data"}).encode('utf-8'))

            elif action == 'fetch':
                if 'file_name' in command:
                    file_name = command['file_name']
                    cur.execute("SELECT * FROM peers WHERE file_name = %s", (file_name,))
                    results = cur.fetchall()
                    if results:
                        peers_info = [{'peers_ip': r[0], 'peers_port': r[1], 'peers_hostname': r[2],
                                       'file_name': r[3], 'file_size': r[4], 'piece_hash': r[5],
                                       'piece_size': r[6], 'num_order_in_file': r[7]}
                                      for r in results if r[2] in active_connections]
                        response = {'peers_info': peers_info, 'tracker_id': TRACKER_ID}
                    else:
                        response = {'peers_info': [], 'warning_message': 'No peers have the file.'}
                    conn.sendall(json.dumps(response).encode('utf-8'))
                else:
                    conn.sendall(json.dumps({"error": "File name required for fetch"}).encode('utf-8'))

            elif action == 'file_list':
                files = command['files']
                print(f"List of files : {files}")
            
            elif action == 'status_update':
                status = command.get('status')
                if status == 'started':
                    log_event(f"Download started for {client_peers_hostname}/{peers_ip}")
                elif status == 'completed':
                    log_event(f"Download completed for {client_peers_hostname}/{peers_ip}")
                elif status == 'stopped':
                    log_event(f"Download stopped for {client_peers_hostname}/{peers_ip}")
                conn.sendall(json.dumps({"tracker_id": TRACKER_ID}).encode('utf-8'))

    except Exception as e:
        logging.exception(f"Error with client {addr}: {e}")
    finally:
        if client_peers_hostname and client_peers_hostname in active_connections:
            del active_connections[client_peers_hostname]
        conn.close()
        log_event(f"Connection with {addr} closed.")

# Request file list from a specific client
def request_file_list_from_client(hostname):
    if hostname in active_connections:
        conn = active_connections[hostname]
        ip_address, _ = conn.getpeername()
        peer_port = 65433
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as peer_sock:
            try:
                peer_sock.connect((ip_address, peer_port))
                request = {'action': 'request_file_list'}
                peer_sock.sendall(json.dumps(request).encode('utf-8') + b'\n')

                # Read response from peer
                response_data = peer_sock.recv(4096).decode('utf-8')
                if response_data.strip():
                    response = json.loads(response_data)
                    if 'files' in response:
                        return response['files']
                    else:
                        return "Error: No file list in response"
                else:
                    log_event("Error: Empty response from peer.")
                    return "Error: Empty response from peer."
            except (socket.error, json.JSONDecodeError) as e:
                log_event(f"Error in requesting file list from {hostname}: {e}")
                return "Error: Connection issue with peer"
    else:
        return "Error: Client not connected"

# Discover files by hostname
def discover_files(peers_hostname):
    files = request_file_list_from_client(peers_hostname)
    print(f"Files on {peers_hostname}: {files}")

# Check if host is online by pinging
def ping_host(peers_hostname):
    is_online = peers_hostname in active_connections
    status = 'online' if is_online else 'offline'
    log_event(f"Host {peers_hostname} is {status}.")

# Server command shell to interact with server
def server_command_shell():
    while True:
        cmd_input = input("Server command: ")
        cmd_parts = cmd_input.split()
        if cmd_parts:
            action = cmd_parts[0]
            if action == "discover" and len(cmd_parts) == 2:
                threading.Thread(target=discover_files, args=(cmd_parts[1],)).start()
            elif action == "ping" and len(cmd_parts) == 2:
                ping_host(cmd_parts[1])
            elif action == "exit":
                break
            else:
                log_event("Unknown command or incorrect usage.")

# Start server to listen for client connections
def start_server(host='0.0.0.0', port=65432):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen()
    log_event("Server started and listening for connections.")

    try:
        while True:
            conn, addr = server_socket.accept()
            threading.Thread(target=client_handler, args=(conn, addr)).start()
            log_event(f"Active connections: {threading.active_count() - 1}")
    except KeyboardInterrupt:
        log_event("Server shutdown requested.")
    finally:
        server_socket.close()
        cur.close()

if __name__ == "__main__":
    SERVER_HOST = '0.0.0.0'
    SERVER_PORT = 65432

    server_thread = threading.Thread(target=start_server, args=(SERVER_HOST, SERVER_PORT))
    server_thread.start()
    server_command_shell()
    print("Server shutdown requested.")
    sys.exit(0)