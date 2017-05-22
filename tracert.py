import socket
import select
import struct
import sys

MAX_ROUNDS = 50
PORT = 33434 + MAX_ROUNDS - 1
CHECKSUM = 63487
ROUND_TIMEOUT = 2   # seconds


class ICMPPacket:
    def __init__(self, type, code, checksum, data=bytes()):
        self.type = type
        self.code = code
        self.checksum = checksum
        self.data = data

    def to_binary(self):
        return struct.pack(">BBHHH", self.type, self.code, self.checksum, 0, 0)

    @staticmethod
    def from_binary(data):
        type, code, checksum = struct.unpack(">BBHHH", data)[:-2]
        return ICMPPacket(type, code, checksum)


def trace_ip(destination_ip: str):
    for ttl in range(1, MAX_ROUNDS):
        icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
        icmp_sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

        packet = ICMPPacket(8, 0, CHECKSUM)
        data = packet.to_binary()

        icmp_sock.sendto(data, (destination_ip, 1))
        ip = try_get_reply(icmp_sock)

        yield ip if ip is not None else "*"

        if ip == destination_ip:
            break


def try_get_reply(sock):
    reading_sock, a, b = select.select([sock], [], [], ROUND_TIMEOUT)

    if len(reading_sock) == 0:
        return None

    icmp_data, address = sock.recvfrom(1024)
    packet = ICMPPacket.from_binary(icmp_data[20:28])

    # time exceeed or reply
    if packet.type == 11 or packet.type == 0:
        return address[0]


def whois(request, server):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        request = socket.gethostbyname(request)
        sock.connect((server, 43))
        sock.sendall(b"%b\n" % request.encode("utf-8"))
        response = ""
        data = sock.recv(1024)
        response += data.decode("utf-8")

        return response


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Default address used(8.8.8.8)")
        address = "8.8.8.8"
    else:
        address = sys.argv[1]

    address = socket.gethostbyname(address)
    current_number = 0
    for ip in trace_ip(address):
        print(str(current_number) + ") ", end="")
        if ip != "*":
            print(ip)
        else:
            print("*")
        current_number += 1
