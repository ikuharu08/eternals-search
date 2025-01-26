import socket
import threading

def handle_client(client_socket):
    # Terima data dari client
    request = client_socket.recv(1024)
    print(f"[*] Received: {request}")

    # Kirim balasan ke client
    client_socket.send(b"ACK")
    client_socket.close()

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
