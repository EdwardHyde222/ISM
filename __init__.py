from Packet_old import Packet as Packet_old
from Packet import Packet


def main():
    new_packet3 = Packet("Hello", 1024)

    counter = 0
    for i in range(10000):
        if new_packet3.data != new_packet3.deploy(new_packet3.encrypted_data):
            counter += 1

    print(counter)

if __name__ == '__main__':
    main()
