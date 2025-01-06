import os
import fcntl
import struct
import socket
import select
from scapy.all import *

# Constants
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

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

    while True:
        print('Before read tun:')
        read_fds, _, _ = select.select([tun, sock], [], [])
        
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
                sock.sendto(data, server_addr)
            elif fd == sock:
                data, server = sock.recvfrom(2048)
                pkt = IP(data)
                print(f'Receive packet from server - {pkt.summary()}')
                os.write(tun, bytes(pkt))

if __name__ == '__main__':
    main()
