import socket
import threading

def handle_client(client_socket):
    # Terima dan proses permintaan dari client
    client_socket.recv(262)  # Terima permintaan awal
    client_socket.send(b"\x05\x00")  # Kirim balasan: SOCKS5, no authentication

    # Terima permintaan koneksi
    request = client_socket.recv(4)
    mode = request[1]
    if mode != 1:  # Hanya mendukung mode CONNECT
        client_socket.close()
        return

    # Terima alamat tujuan
    address_type = request[3]
    if address_type == 1:  # IPv4
        address = socket.inet_ntoa(client_socket.recv(4))
    elif address_type == 3:  # Domain name
        domain_length = client_socket.recv(1)[0]
        address = client_socket.recv(domain_length)
    else:
        client_socket.close()
        return

    port = int.from_bytes(client_socket.recv(2), 'big')
    try:
        # Buat koneksi ke alamat tujuan
        remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_socket.connect((address, port))

        # Kirim balasan sukses ke client
        client_socket.send(b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + (1080).to_bytes(2, 'big'))

        # Teruskan data antara client dan remote
        threading.Thread(target=forward, args=(client_socket, remote_socket)).start()
        threading.Thread(target=forward, args=(remote_socket, client_socket)).start()
    except Exception as e:
        client_socket.close()

def forward(source, destination):
    while True:
        data = source.recv(4096)
        if len(data) == 0:
            break
        destination.send(data)
    source.close()
    destination.close()

def main():
    # Buat socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind ke alamat dan port
    server.bind(("0.0.0.0", 1080))

    # Listen untuk koneksi masuk
    server.listen(5)
    print("[*] Listening on 0.0.0.0:1080")

    while True:
        # Terima koneksi dari client
        client_socket, addr = server.accept()
        print(f"[*] Accepted connection from {addr[0]}:{addr[1]}")

        # Handle client di thread terpisah
        client_handler = threading.Thread(target=handle_client, args=(client_socket,))
        client_handler.start()

if __name__ == "__main__":
    main()
