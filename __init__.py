from Packet import Packet, Decrypt


def main():

    for i in range(10):
        new_packet3 = Packet(input())
        print(new_packet3.encrypted_data)
        print(Decrypt().decrypt(new_packet3))


if __name__ == '__main__':
    main()
