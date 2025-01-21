# miniVPN
This is a mini-project program that aims to illustrate the mechanism for implementing a Virtual Private Network (VPN). This program helps us understand computer networks and security.

## How to run the code
```
# First of all, run the server code on a computer that acts as a VPN server.
python vpn_server.py
# In the same machine, add an iptable rule
iptables -t nat -A POSTROUTING -s 10.64.0.0/24 -o ens160 -j MASQUERADE
# In the computer acts as a VPN client, start the VPN client program
python vpn_client.py
# In the VPN client machine, add the following route rule if not exist
10.245.249.0    10.64.0.100     255.255.255.0   UG    0      0        0 tun0
10.64.0.0       0.0.0.0         255.255.255.0   U     0      0        0 tun0
```
