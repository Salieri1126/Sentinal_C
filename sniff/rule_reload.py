#!/usr/bin/python3

# When a signal is sent to UDP port 21119, the policy is read again from dbms_ips.
import socket
import time

if __name__ == '__main__':
    addr = ('192.168.1.19', 21119)

    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    client.sendto(str.encode(" "), addr)

    time.sleep(1)
    client.close()

