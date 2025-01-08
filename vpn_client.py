import os
import json
import fcntl
import struct
import socket
import select

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from scapy.all import *

# Constants
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

G_DH_PARAMS = '''
-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEAtBrTj2B79n0139/K2Xis4fP+Y9gTJBFpmuezGpPAWarmeRyMgb6F
EAsD9oGNtGHgTIHZ/XeuR5pg/4wIHSohmjLRy1vkMYJ2dnPfH+Ip5Mz85wsJJMzx
InX35XhJCaVe5pH5jlIb7LBA8NpOLin0ElTAu+8zrztm6RpCfkwa4mtV4CSvoKfK
sCewwZsYA+0qPxTAqBZqSOY1MrrOgFGG7RoVFN48CeBjQywb/o2sQWG2uNm43NaU
cFFZJ1YJSbgsWdX/sFWDAdSDAE1QExoCk2nk0YTNlS4LYmQnCqNbopsAGAAC8POv
fdGHy1vegQVzMFANuHQXf8LiL31hzAVdLwIBAg==
-----END DH PARAMETERS-----
'''

client_hello = {
    'shared_key_generation': {
        'alg': 'DH',
        'parameters': G_DH_PARAMS,
        'public_key': None,
    },
    'encryption_alg': 'AES-256-ctr',
}
server_hello = None


class SecureTunnelClient:
    def __init__(self, server_ip, server_port):
        self.server_ip = server_ip
        self.server_port = server_port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.dh_parameters = None
        self.shared_key = None
        self.private_key = None
        self.encryptor = None
        self.decryptor = None

    def send_client_hello(self):
        if client_hello['shared_key_generation']['parameters'] is None:
            self.dh_parameters = dh.generate_parameters(generator=2, key_size=2048)
            pem_parameters = self.dh_parameters.parameter_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.ParameterFormat.PKCS3
            )
            client_hello['shared_key_generation']['parameters'] = pem_parameters.decode()
        else:
            self.dh_parameters = serialization.load_pem_parameters(
                client_hello['shared_key_generation']['parameters'].encode()
            )
        self.private_key = self.dh_parameters.generate_private_key()
        pem_public_key = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        client_hello['shared_key_generation']['public_key'] = pem_public_key.decode()
        self.sock.sendto(json.dumps(client_hello).encode(), (self.server_ip, self.server_port))

    def receive_server_hello(self):
        server_hello, server = self.sock.recvfrom(2048)
        server_hello = json.loads(server_hello.decode())
        peer_pub_key = serialization.load_pem_public_key(
            server_hello['shared_key_generation']['public_key'].encode())
        self.shared_key = self.private_key.exchange(peer_pub_key)
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
        cipher = Cipher(
            algorithms.AES(self.c2s_enc_key), modes.CTR(self.c2s_iv),
            backend=default_backend()
        )
        self.encryptor = cipher.encryptor()
        cipher2 = Cipher(
            algorithms.AES(self.s2c_enc_key), modes.CTR(self.s2c_iv),
            backend=default_backend()
        )
        self.decryptor = cipher2.decryptor()

    def handshake(self):
        self.send_client_hello()
        self.receive_server_hello()

    def sendto(self, data):
        ciphertext = self.encryptor.update(data)
        print(ciphertext)
        self.sock.sendto(ciphertext, (self.server_ip, self.server_port))

    def recvfrom(self, length):
        ciphertext, server = self.sock.recvfrom(length)
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
    os.system(f'ip addr add 10.64.0.100/24 dev {tun_name}')
    os.system(f'ip link set dev {tun_name} up')
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_addr = ('10.245.251.15', 5555)
    secure_client = SecureTunnelClient(server_addr[0], server_addr[1])
    secure_client.handshake()

    while True:
        print('Before read tun:')
        read_fds, _, _ = select.select([tun, secure_client.sock], [], [])
        
        for fd in read_fds:
            if fd == tun:
                packet = os.read(tun, 2048)
                ip = IP(packet)
                ip.show()
                if ip.version == 6:
                    continue
                print(f'Sent packet to server - {ip.summary()}')
                data = bytes(ip)
                print(data)
                secure_client.sendto(data)
            elif fd == secure_client.sock:
                data, server = secure_client.recvfrom(2048)
                pkt = IP(data)
                print(f'Receive packet from server - {pkt.summary()}')
                os.write(tun, bytes(pkt))


if __name__ == '__main__':
    main()
