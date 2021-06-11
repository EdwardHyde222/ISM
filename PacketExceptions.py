class PacketExceptions:
    def __init__(self):
        self.__version = '16.05.2021 / P-Exceptions v.1'
        self.__errors = {
            'IndexError': 0,
            'ValueError': 0,
            'Exception': 0,
            'BufferError': 0,
            'PacketEncryptionError': 0,
        }

    def analyze(self, error_type: str = None) -> None:
        for types in self.__errors:
            if error_type == types:
                self.__errors[types] += 1

    def get(self, error_type: str = None) -> int:
        if error_type is not None:
            for item in self.__errors:
                if error_type == item:
                    return int(self.__errors[item])
                    break

    def print(self, error_type: str = None) -> None:
        if error_type is not None:
            for item in self.__errors:
                if error_type == item:
                    print("{} x{}".format(item, self.__errors[item]))
                    break
        else:
            print('+-------------------+')
            for item in self.__errors:
                print("{} x{}".format(item, self.__errors[item]))
            print('+-------------------+')
