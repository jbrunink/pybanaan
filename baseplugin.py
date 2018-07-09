class BasePlugin():
    commandprefix = None
    command = None
    bot = None

    def __init__(self, bot=None, command=None, commandprefix=None):
        self.commandprefix = commandprefix
        self.command = command
        self.bot = bot