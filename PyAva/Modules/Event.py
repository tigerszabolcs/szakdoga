class Event:
    def __init__(self):
        self.__observers = []

    def register(self, observer):
        self.__observers.append(observer)

    def notify(self, *args, **kwargs):
        for observer in self.__observers:
            observer(*args, **kwargs)