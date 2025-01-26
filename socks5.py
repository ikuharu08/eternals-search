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

            # Lanjutkan proses autentikasi...
            # ... kode lainnya ...
        except Exception as e:
            logging.error(f"Error handling client: {str(e)}")
            client_socket.close()

    def _handle_auth(self, client_socket):
        """Handle SOCKS5 authentication"""
        try:
            # Receive auth methods
            header = client_socket.recv(2)
            if len(header) < 2:
                logging.error("Failed to receive auth header")
                return False
                
            version, nmethods = header[0], header[1]
            
            # Check SOCKS version
            if version != self.SOCKS_VERSION:
                logging.error("Invalid SOCKS version")
                return False
                
            # Get available methods
            methods = self._get_available_methods(nmethods, client_socket)
            if not methods:
                return False
            
            # Accept only no authentication for now
            if 0 not in methods:
                logging.error("No acceptable authentication method")
                client_socket.send(bytes([self.SOCKS_VERSION, 255]))
                return False
                
            # Send no authentication required
            client_socket.send(bytes([self.SOCKS_VERSION, 0]))
            return True
            
        except Exception as e:
            logging.error(f"Authentication error: {str(e)}")
            return False

    def _get_available_methods(self, nmethods, client_socket):
        methods = []
        try:
            for i in range(nmethods):
                method = client_socket.recv(1)
                if not method:
                    logging.error("Failed to receive auth methods")
                    return []
                methods.append(method[0])
            return methods
        except Exception as e:
            logging.error(f"Error receiving methods: {str(e)}")
            return []

    def _handle_request(self, client_socket):
        try:
            # Receive request header
            header = client_socket.recv(4)
            if len(header) < 4:
                logging.error("Failed to receive request header")
                return False
                
            version, cmd, _, address_type = header
            
            if version != self.SOCKS_VERSION:
                return False
                
            if cmd != 1:  # Only support CONNECT
                logging.error("Unsupported command")
                self._send_reply(client_socket, 7)
                return False

            if address_type == 1:  # IPv4
                address = socket.inet_ntoa(client_socket.recv(4))
            elif address_type == 3:  # Domain name
                domain_length = client_socket.recv(1)[0]
                address = client_socket.recv(domain_length).decode()
            else:
                logging.error("Unsupported address type")
                self._send_reply(client_socket, 8)
                return False

            # Get port
            port = int.from_bytes(client_socket.recv(2), 'big')
            
            try:
                # Connect to destination
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.connect((address, port))
                bind_address = remote.getsockname()
                logging.info(f"Connected to {address}:{port}")
                
                # Send success reply
                self._send_reply(client_socket, 0, bind_address)
                
            except Exception as e:
                logging.error(f"Connection error: {str(e)}")
                self._send_reply(client_socket, 4)
                return False

            # Start forwarding data
            self._forward_data(client_socket, remote)
            return True
            
        except Exception as e:
            logging.error(f"Request error: {str(e)}")
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
