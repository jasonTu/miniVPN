import os
import fcntl
import struct
import socket
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
    os.system(f'ip addr add 10.64.0.101/24 dev {tun_name}')
    os.system(f'ip link set dev {tun_name} up')
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', 5555))

    while True:
        print('Wait data from client or local tun device:')
        read_fds, _, _ = select.select([sock, tun], [], [])

        for fd in read_fds:
            if fd == sock:
                print('Data received on socket')
                data, client = sock.recvfrom(2048)
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
                sock.sendto(bytes(ip), client)


if __name__ == '__main__':
    main()
