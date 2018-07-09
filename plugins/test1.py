import baseplugin

class Plugin_test1(baseplugin.BasePlugin):
    def on_pubmsg(self, connection, event):
        print('joekel')