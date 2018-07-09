class BasePlugin():
    prefix = None
    command = None

    def __init__(self, prefix, command):
        self.prefix = prefix
        self.command = command
