import socket
import threading
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
import os

class SecurityParams:
    def __init__(self):
        self.aes_key = None
        self.iv = None
        self.shared_secret = None
        self.private_key = None
        self.public_key = None
        
    def generate_keypair(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()

class ZigbeeServer:
    def __init__(self, host='localhost', port=5000):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.security = SecurityParams()
        self.security.generate_keypair()

    def start(self):
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(1)
        print(f"Server listening on {self.host}:{self.port}")
        
        while True:
            client_socket, addr = self.server_socket.accept()
            client_handler = threading.Thread(
                target=self.handle_client,
                args=(client_socket,)
            )
            client_handler.start()

    def handle_client(self, client_socket):
        try:
            # Step 1: Send public key
            pub_key_pem = self.security.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            client_socket.send(pub_key_pem)

            # Step 2: Receive encrypted shared secret
            encrypted_secret = client_socket.recv(256)
            shared_secret = self.security.private_key.decrypt(
                encrypted_secret,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Step 3: Derive session key using HKDF
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake'
            )
            self.security.aes_key = hkdf.derive(shared_secret)
            self.security.iv = os.urandom(16)
            
            # Step 4: Send IV to client
            client_socket.send(self.security.iv)
            
            # Handle encrypted communication
            while True:
                cipher = Cipher(
                    algorithms.AES(self.security.aes_key),
                    modes.CBC(self.security.iv)
                )
                decryptor = cipher.decryptor()
                
                # Receive encrypted message
                encrypted_msg = client_socket.recv(1024)
                if not encrypted_msg:
                    break
                    
                # Decrypt message
                padded_msg = decryptor.update(encrypted_msg) + decryptor.finalize()
                msg = padded_msg.rstrip(b'\0')
                print(f"Received: {msg.decode()}")
                
                # Send encrypted response
                response = b"Server received: " + msg
                encryptor = cipher.encryptor()
                padded_response = response + b'\0' * (16 - (len(response) % 16))
                encrypted_response = encryptor.update(padded_response) + encryptor.finalize()
                client_socket.send(encrypted_response)

        except Exception as e:
            print(f"Error handling client: {e}")
        finally:
            client_socket.close()

class ZigbeeClient:
    def __init__(self, host='localhost', port=5000):
        self.host = host
        self.port = port
        self.security = SecurityParams()

    def connect(self):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((self.host, self.port))
        
        try:
            # Step 1: Receive server's public key
            server_public_key_pem = client_socket.recv(1024)
            server_public_key = serialization.load_pem_public_key(server_public_key_pem)
            
            # Step 2: Generate and send encrypted shared secret
            shared_secret = secrets.token_bytes(32)
            encrypted_secret = server_public_key.encrypt(
                shared_secret,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            client_socket.send(encrypted_secret)
            
            # Step 3: Derive session key using HKDF
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake'
            )
            self.security.aes_key = hkdf.derive(shared_secret)
            
            # Step 4: Receive IV from server
            self.security.iv = client_socket.recv(16)
            
            # Send encrypted messages
            while True:
                message = input("Enter message (or 'quit' to exit): ")
                if message.lower() == 'quit':
                    break
                
                cipher = Cipher(
                    algorithms.AES(self.security.aes_key),
                    modes.CBC(self.security.iv)
                )
                encryptor = cipher.encryptor()
                
                # Pad message and encrypt
                padded_msg = message.encode() + b'\0' * (16 - (len(message.encode()) % 16))
                encrypted_msg = encryptor.update(padded_msg) + encryptor.finalize()
                client_socket.send(encrypted_msg)
                
                # Receive and decrypt response
                encrypted_response = client_socket.recv(1024)
                decryptor = cipher.decryptor()
                padded_response = decryptor.update(encrypted_response) + decryptor.finalize()
                response = padded_response.rstrip(b'\0')
                print(f"Server response: {response.decode()}")

        except Exception as e:
            print(f"Error: {e}")
        finally:
            client_socket.close()

# Example usage:
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python script.py [server|client]")
        sys.exit(1)
        
    if sys.argv[1] == "server":
        server = ZigbeeServer()
        server.start()
    elif sys.argv[1] == "client":
        client = ZigbeeClient()
        client.connect()
