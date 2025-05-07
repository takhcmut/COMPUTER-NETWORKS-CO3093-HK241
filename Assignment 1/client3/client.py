import socket
import json
import os
import threading
import shlex
import hashlib
import time
import math
import sys

stop_event = threading.Event()

download_progress = {}
def update_progress(file_name, piece_number):
    if file_name not in download_progress:
        download_progress[file_name] = []
    download_progress[file_name].append(piece_number)
    print(f"Progress for {file_name}: {len(download_progress[file_name])} pieces downloaded.")

def calculate_piece_hash(piece_data):
    sha1 = hashlib.sha1()
    sha1.update(piece_data)
    return sha1.digest()

def create_pieces_string(pieces):
    hash_pieces = []
    for piece_file_path in pieces:
        with open(piece_file_path, "rb") as piece_file:
            piece_data = piece_file.read()
            piece_hash = calculate_piece_hash(piece_data)
            hash_pieces.append(f"{piece_hash}")
    return hash_pieces

def split_file_into_pieces(file_path, piece_length):
    pieces = []
    with open(file_path, "rb") as file:
        counter = 1
        while True:
            piece_data = file.read(piece_length)
            if not piece_data:
                break
            piece_file_path = f"{file_path}_piece{counter}"
            with open(piece_file_path, "wb") as piece_file:
                piece_file.write(piece_data)
            pieces.append(piece_file_path)
            counter += 1
    return pieces

def merge_pieces_into_file(pieces, output_file_path):
    with open(output_file_path, "wb") as output_file:
        for piece_file_path in pieces:
            with open(piece_file_path, "rb") as piece_file:
                piece_data = piece_file.read()
                output_file.write(piece_data)

def get_list_local_files(directory='.'):
    try:
        return [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
    except Exception as e:
        return f"Error: Unable to list files - {e}"

def check_local_files(file_name):
    return os.path.exists(file_name)

def check_local_piece_files(file_name):
    exist_files = []
    directory = os.getcwd()
    for filename in os.listdir(directory):
        if filename.startswith(file_name) and len(filename) > len(file_name):
            exist_files.append(filename)
    return exist_files if exist_files else False

def handle_publish_piece(sock, peers_port, pieces, file_name, file_size, piece_size):
    pieces_hash = create_pieces_string(pieces)
    user_input_num_piece = input(f"File {file_name} has pieces: {pieces}\nPiece hashes: {pieces_hash}.\nSelect piece numbers to publish: ")
    num_order_in_file = shlex.split(user_input_num_piece)
    piece_hash = []
    print("You was selected: " )
    for i in num_order_in_file:
        index = pieces.index(f"{file_name}_piece{i}")
        piece_hash.append(pieces_hash[index])
        print(f"Selected Number {i}: {pieces_hash[index]}")
    publish_piece_file(sock, peers_port, file_name, file_size, piece_hash, piece_size, num_order_in_file)

def publish_piece_file(sock, peers_port, file_name, file_size, piece_hash, piece_size, num_order_in_file):
    peers_hostname = socket.gethostname()
    command = {
        "action": "publish",
        "peers_port": peers_port,
        "peers_hostname": peers_hostname,
        "file_name": file_name,
        "file_size": file_size,
        "piece_hash": piece_hash,
        "piece_size": piece_size,
        "num_order_in_file": num_order_in_file,
    }
    sock.sendall(json.dumps(command).encode('utf-8') + b'\n')
    response = sock.recv(4096).decode('utf-8')
    print(response)

def request_file_from_peer(peers_ip, peer_port, file_name, piece_hash, num_order_in_file):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as peer_sock:
        try:
            peer_sock.connect((peers_ip, int(peer_port)))
            peer_sock.sendall(json.dumps({'action': 'send_file', 'file_name': file_name,
                                          'piece_hash': piece_hash, 'num_order_in_file': num_order_in_file}).encode('utf-8') + b'\n')
            
            with open(f"{file_name}_piece{num_order_in_file}", 'wb') as f:
                while True:
                    data = peer_sock.recv(4096)
                    if not data:
                        break
                    f.write(data)

            print(f"Downloaded piece: {file_name}_piece{num_order_in_file} from {peers_ip}:{peer_port}")
        
        except Exception as e:
            print(f"Failed to connect to peer {peers_ip}:{peer_port} for piece {num_order_in_file} - {e}")

def rarest_first(peers_info):
    piece_count = {}
    for peer in peers_info:
        pieces = peer['num_order_in_file']
        for piece in pieces:
            piece_count[piece] = piece_count.get(piece, 0) + 1

    return sorted(
        peers_info, 
        key=lambda peer: min(piece_count[piece] for piece in peer['num_order_in_file'])
    )

def fetch_piece_multithreaded(peer_info, file_name):
    """
    Download a single piece from a peer concurrently and update progress.
    """
    request_file_from_peer(peer_info['peers_ip'], peer_info['peers_port'], file_name,
                           peer_info['piece_hash'], peer_info['num_order_in_file'])
    # Track the download progress for each piece
    update_progress(file_name, peer_info['num_order_in_file'])

def fetch_file(sock, peers_port, file_name, piece_hash, num_order_in_file):
    """
    Request pieces of the specified file from multiple peers and download concurrently.
    """
    # Prepare and send fetch request
    peers_hostname = socket.gethostname()
    command = {
        "action": "fetch",
        "peers_port": peers_port,
        "peers_hostname": peers_hostname,
        "file_name": file_name,
        "piece_hash": piece_hash,
        "num_order_in_file": num_order_in_file,
    }
    sock.sendall(json.dumps(command).encode('utf-8') + b'\n')
    
    # Receive and process response
    try:
        response = json.loads(sock.recv(4096).decode('utf-8'))
    except json.JSONDecodeError:
        print("Error: Failed to decode tracker response.")
        return
    
    if 'peers_info' not in response:
        print("Error: Incorrect response format from tracker.")
        return
    
    # Process peers_info list
    peers_info = rarest_first(response['peers_info'])
    if not peers_info:
        print(f"No peers currently have the file {file_name}.")
        return
    
    # Display available peers for the file
    host_info_str = "\n".join([
        f"Number: {peer_info['num_order_in_file']} {peer_info['peers_hostname']}/{peer_info['peers_ip']}:{peer_info['peers_port']} piece_hash: {peer_info['piece_hash']}"
        for peer_info in peers_info
    ])
    print(f"Hosts with the file {file_name}:\n{host_info_str}")
    
    # Start threads to download pieces from peers
    threads = []
    for peer_info in peers_info:
        t = threading.Thread(target=fetch_piece_multithreaded, args=(peer_info, file_name))
        threads.append(t)
        t.start()

    # Wait for all threads to finish downloading
    for t in threads:
        t.join()

    # Verify and merge pieces if download is complete
    pieces = check_local_piece_files(file_name)
    total_pieces = math.ceil(int(peers_info[0]['file_size']) / int(peers_info[0]['piece_size']))
    
    if total_pieces == len(sorted(pieces)):
        merge_pieces_into_file(pieces, file_name)
        print(f"File {file_name} downloaded successfully with all {total_pieces} pieces.")
        send_status_update(sock, peers_port, 'completed', file_name)
    else:
        missing_pieces = total_pieces - len(pieces)
        print(f"Download incomplete for {file_name}. {missing_pieces} pieces are missing.")


def send_status_update(sock, peers_port, status, file_name=""):
    command = {
        "action": "status_update",
        "peers_port": peers_port,
        "peers_hostname": socket.gethostname(),
        "file_name": file_name,
        "status": status
    }
    sock.sendall(json.dumps(command).encode('utf-8') + b'\n')

def send_piece_to_client(conn, piece):
    with open(piece, 'rb') as f:
        while True:
            bytes_read = f.read(4096)
            if not bytes_read:
                break
            conn.sendall(bytes_read)

def handle_file_request(conn, shared_files_dir):
    try:
        data = conn.recv(4096).decode('utf-8')
        command = json.loads(data)
        if command['action'] == 'send_file':
            file_name = command['file_name']
            num_order_in_file = command['num_order_in_file']
            file_path = os.path.join(shared_files_dir, f"{file_name}_piece{num_order_in_file}")
            send_piece_to_client(conn, file_path)
        elif command['action'] == 'request_file_list':
            files = get_list_local_files(shared_files_dir)
            response = {'files': files}  # Respond with the list of local files
            conn.sendall(json.dumps(response).encode('utf-8'))
    finally:
        conn.close()

def start_host_service(port, shared_files_dir):
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(('0.0.0.0', port))
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.listen()
    while not stop_event.is_set():
        try:
            server_sock.settimeout(1)
            conn, addr = server_sock.accept()
            thread = threading.Thread(target=handle_file_request, args=(conn, shared_files_dir))
            thread.start()
        except socket.timeout:
            continue
        except Exception as e:
            print(f"Host service error: {e}")
            break
    server_sock.close()

def connect_to_server(server_host, server_port, peers_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)  # Set a 10-second timeout for connecting to the server
    try:
        sock.connect((server_host, server_port))
        peers_hostname = socket.gethostname()
        sock.sendall(json.dumps({'action': 'introduce', 'peers_hostname': peers_hostname, 'peers_port': peers_port}).encode('utf-8') + b'\n')
        return sock
    except socket.timeout:
        print("Connection to server timed out.")
        sys.exit(1)

def main(server_host, server_port, peers_port):
    host_service_thread = threading.Thread(target=start_host_service, args=(peers_port, './'))
    host_service_thread.start()
    sock = connect_to_server(server_host, server_port, peers_port)

    try:
        while True:
            user_input = input("Enter command (publish file_name/ fetch file_name/ exit): ")
            command_parts = shlex.split(user_input)
            
            if len(command_parts) == 2 and command_parts[0].lower() == 'publish':
                _, file_name = command_parts
                if check_local_files(file_name):
                    piece_size = 524288
                    file_size = os.path.getsize(file_name)
                    pieces = split_file_into_pieces(file_name, piece_size)
                    handle_publish_piece(sock, peers_port, pieces, file_name, file_size, piece_size)
                elif (pieces := check_local_piece_files(file_name)):
                    handle_publish_piece(sock, peers_port, pieces, file_name, os.path.getsize(file_name), 524288)
                else:
                    print(f"Local file {file_name}/piece does not exist.")
                continue
            
            if len(command_parts) >= 2 and command_parts[0].lower() == 'fetch':
                files_to_fetch = command_parts[1:]
                threads = []
                for file_name in files_to_fetch:
                    pieces = check_local_piece_files(file_name)
                    pieces_hash = [] if not pieces else create_pieces_string(pieces)
                    num_order_in_file = [] if not pieces else [item.split("_")[-1][5:] for item in pieces]
                    t = threading.Thread(target=fetch_file, args=(sock, peers_port, file_name, pieces_hash, num_order_in_file))
                    threads.append(t)
                    t.start()
                for t in threads:
                    t.join()
            
            elif user_input.lower() == 'exit':
                send_status_update(sock, peers_port, 'stopped', "")
                stop_event.set()
                sock.close()
                break
            
            else:
                print("Invalid command.")
    finally:
        sock.close()
        host_service_thread.join()

if __name__ == "__main__":
    SERVER_HOST = 'localhost'
    SERVER_PORT = 65432
    CLIENT_PORT = 65435
    main(SERVER_HOST, SERVER_PORT, CLIENT_PORT)