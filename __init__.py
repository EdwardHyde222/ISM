from time import sleep

from Decrypt import Decrypt
from Packet import Packet


def main():
    ## Шифровка пакета
    packet = Packet(input(), parsing_method='shuffle')
    print(packet.encrypted())

    ## Дешифровка строки
    print(Decrypt().decrypt(input()))

def decrypt():
    print(Decrypt().decrypt(input()))

def ecnrypt():
    print(Packet(input(), parsing_counter=64).encrypted_data)

# Again
# 9HU5ELDLLDLLGOLRS13CLGOLEMLJRL1AL4DL1SARS1AILGSPBZZF6VZYF8ACDU7LEMLRS17GLDLL1AL4DLRS1LTLGOLRS1KSL5EL5ELRS1QYLGOLICI0DFVUX4FKJXAG1S91MCMULRS11AL7GL1ALAILFNL9SICP
# 9HU5ELDLLDLLGOLRS13CLGOLEMLJRL1AL4DL1SARS1AILGSPI5HOAAV0WUK9XBVVEMLRS17GLDLL1AL4DLRS1LTLGOLRS1KSL5EL5ELRS1QYLGOL4P95G7JZ8UT0CKAKU49B5FMULRS11AL7GL1ALAILFNL9SIN3
if __name__ == '__main__':
    main()
