import socket
import threading
import logging
import select
import sys

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class SOCKS5Server:
    SOCKS_VERSION = 5
    
    def __init__(self, host='0.0.0.0', port=1080):
        self.host = host
        self.port = port

    def handle_client(self, client_socket):
        try:
            # Menerima header (2 byte)
            header = self._recvall(client_socket, 2)
            if not header:
                logging.error("Failed to receive header")
                client_socket.close()
                return

            version, nmethods = header[0], header[1]

            # Pastikan versi SOCKS sesuai
            if version != self.SOCKS_VERSION:
                logging.error("Invalid SOCKS version")
                client_socket.close()
                return

            # Menerima daftar metode autentikasi
            methods = self._recvall(client_socket, nmethods)
            if not methods:
                logging.error("Failed to receive authentication methods")
                client_socket.close()
                return

            # Lakukan autentikasi
            if not self._handle_auth(client_socket):
                client_socket.close()
                return

            # Tangani permintaan client
            if not self._handle_request(client_socket):
                client_socket.close()
                return

        except Exception as e:
            logging.error(f"Error handling client: {str(e)}")
            client_socket.close()

    def _handle_auth(self, client_socket):
        """Handle SOCKS5 authentication"""
        try:
            # Mengirimkan respons bahwa tidak diperlukan autentikasi
            client_socket.sendall(bytes([self.SOCKS_VERSION, 0]))
            return True
        except Exception as e:
            logging.error(f"Authentication error: {str(e)}")
            return False

    def _handle_request(self, client_socket):
        """Handle SOCKS5 client request"""
        try:
            # Menerima header permintaan (4 byte)
            header = self._recvall(client_socket, 4)
            if not header:
                logging.error("Failed to receive request header")
                return False

            version, cmd, _, address_type = header

            if version != self.SOCKS_VERSION:
                logging.error("Invalid SOCKS version in request")
                return False

            if cmd != 1:
                logging.error("Unsupported command")
                self._send_reply(client_socket, 7)
                return False

            # Menangani alamat tujuan berdasarkan tipe
            if address_type == 1:  # IPv4
                addr = self._recvall(client_socket, 4)
                address = socket.inet_ntoa(addr)
            elif address_type == 3:  # Domain name
                domain_length = self._recvall(client_socket, 1)[0]
                domain = self._recvall(client_socket, domain_length)
                address = domain.decode()
            else:
                logging.error("Unsupported address type")
                self._send_reply(client_socket, 8)
                return False

            # Menerima port tujuan
            port_bytes = self._recvall(client_socket, 2)
            port = int.from_bytes(port_bytes, 'big')

            # Mencoba terhubung ke server tujuan
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.connect((address, port))
            logging.info(f"Connected to {address}:{port}")

            # Mengirimkan respons sukses ke client
            bind_address = remote.getsockname()
            self._send_reply(client_socket, 0, bind_address)

            # Meneruskan data antara client dan server tujuan
            self._forward_data(client_socket, remote)
            return True

        except Exception as e:
            logging.error(f"Request handling error: {str(e)}")
            self._send_reply(client_socket, 1)
            return False

    def _send_reply(self, client_socket, reply_code, bind_address=None):
        """Send SOCKS5 reply"""
        if bind_address is None:
            bind_address = ('0.0.0.0', 0)
        
        addr_bytes = socket.inet_aton(bind_address[0])
        port_bytes = bind_address[1].to_bytes(2, 'big')
        
        reply = bytes([
            self.SOCKS_VERSION,
            reply_code,
            0,  # Reserved
            1,  # IPv4
        ]) + addr_bytes + port_bytes
        
        client_socket.send(reply)

    def _forward_data(self, client_socket, remote_socket):
        """Forward data between client and remote using select"""
        while True:
            # Wait until client or remote is available for read
            r, w, e = select.select([client_socket, remote_socket], [], [])
            
            if client_socket in r:
                data = client_socket.recv(4096)
                if not data:
                    break
                remote_socket.send(data)
                
            if remote_socket in r:
                data = remote_socket.recv(4096)
                if not data:
                    break
                client_socket.send(data)
                
        client_socket.close()
        remote_socket.close()

    def start(self):
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.host, self.port))
            server.listen(100)
            
            logging.info(f"SOCKS5 server listening on {self.host}:{self.port}")
            
            while True:
                client_socket, addr = server.accept()
                logging.info(f"Accepted connection from {addr[0]}:{addr[1]}")
                
                client_handler = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket,)
                )
                client_handler.daemon = True
                client_handler.start()
                
        except Exception as e:
            logging.error(f"Server error: {str(e)}")
            server.close()
            sys.exit(1)

    def _recvall(self, sock, n):
        """Menerima tepat n byte data dari socket"""
        data = b''
        while len(data) < n:
            packet = sock.recv(n - len(data))
            if not packet:
                return None
            data += packet
        return data

if __name__ == "__main__":
    server = SOCKS5Server()
    server.start()
