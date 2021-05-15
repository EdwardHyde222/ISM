from time import sleep

from Decrypt import Decrypt
from Packet import Packet


def main():
    ## Шифровка пакета
    packet = Packet(input(), parsing_method=64)
    print(packet.encrypted_data)

    ## Дешифровка строки
    print(Decrypt().decrypt(input()))

if __name__ == '__main__':
    main()
