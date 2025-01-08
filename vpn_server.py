import os
import json
import fcntl
import struct
import socket

from scapy.all import *
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# Constants
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

server_hello = {
    'shared_key_generation': {
        'public_key': None,
    }
}

class SecureTunnelServer:
    def __init__(self, server_ip, server_port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_ip = server_ip
        self.server_port = server_port
        self.sock.bind((server_ip, server_port))
        self.dh_parameters = None
        self.shared_key = None
        self.private_key = None
        self.encryptor = None
        self.decryptor = None

    def derive_keys(self):
        # Perform key derivation.
        self.c2s_enc_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'ctos encryption key',
        ).derive(self.shared_key)
        self.c2s_iv = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'ctos iv',
        ).derive(self.shared_key)[:16]
        self.s2c_enc_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'stoc encryption key',
        ).derive(self.shared_key)
        self.s2c_iv = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'stoc iv',
        ).derive(self.shared_key)[:16]

    def receive_client_hello(self):
        client_hello, self.client = self.sock.recvfrom(2048)
        print(client_hello)
        client_hello = json.loads(client_hello.decode())
        pem_pub_key = client_hello['shared_key_generation']['public_key'].encode()
        peer_pub_key = serialization.load_pem_public_key(pem_pub_key)
        self.dh_parameters = serialization.load_pem_parameters(
            client_hello['shared_key_generation']['parameters'].encode()
        )
        self.private_key = self.dh_parameters.generate_private_key()
        self.shared_key = self.private_key.exchange(peer_pub_key)
        self.derive_keys()
        cipher = Cipher(
            algorithms.AES(self.s2c_enc_key), modes.CTR(self.s2c_iv),
            backend=default_backend()
        )
        self.encryptor = cipher.encryptor()
        cipher2 = Cipher(
            algorithms.AES(self.c2s_enc_key), modes.CTR(self.c2s_iv),
            backend=default_backend()
        )
        self.decryptor = cipher2.decryptor()

    def send_server_hello(self):
        pub_key = self.private_key.public_key()
        pem_pub_key = pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        server_hello['shared_key_generation']['public_key'] = pem_pub_key.decode()
        self.sock.sendto(json.dumps(server_hello).encode(), self.client)

    def handshake(self):
        self.receive_client_hello()
        self.send_server_hello()

    def sendto(self, data, remote_addr):
        ciphertext = self.encryptor.update(data)
        self.sock.sendto(ciphertext, remote_addr)

    def recvfrom(self, length):
        ciphertext, server = self.sock.recvfrom(length)
        print(ciphertext)
        data = self.decryptor.update(ciphertext)
        return data, server


def create_tun_device(name):
    tun = os.open('/dev/net/tun', os.O_RDWR)
    ifr = struct.pack('16sH', name.encode('utf-8'), IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(tun, TUNSETIFF, ifr)
    return tun


def main():
    tun_name = 'tun0'
    tun = create_tun_device(tun_name)
    os.system(f'ip addr add 10.64.0.101/24 dev {tun_name}')
    os.system(f'ip link set dev {tun_name} up')
    secure_server = SecureTunnelServer('0.0.0.0', 5555)
    secure_server.handshake()

    while True:
        print('Wait data from client or local tun device:')
        read_fds, _, _ = select.select([secure_server.sock, tun], [], [])

        for fd in read_fds:
            if fd == secure_server.sock:
                print('Data received on socket')
                data, client = secure_server.recvfrom(2048)
                pkt = IP(data)
                print(f'Packet from client - {pkt.summary()}')
                os.write(tun, bytes(pkt))
            elif fd == tun:
                print('Data received on tun device')
                packet = os.read(tun, 2048)
                ip = IP(packet)
                print(ip.show())
                if ip.version == 6:
                    continue
                print(f'Send to client - {ip.summary()}')
                secure_server.sendto(bytes(ip), client)


if __name__ == '__main__':
    main()
