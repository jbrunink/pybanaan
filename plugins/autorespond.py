import baseplugin
import utils

import dns.resolver
import dns.name
import dns.reversename
import dns.rdatatype
import dns.rrset
import dns.exception
import shlex
import ipaddress

import pprint

class Plugin_autorespond(baseplugin.BasePlugin):
    def on_pubmsg(self, connection, event, bot):
        if event.source.startswith('Telegram!'):
            message = event.arguments[0]
            event.source = message[:message.index(':')]
            event.arguments[0] = message[(message.index(':')+2):]
            bot._dispatcher(connection, event)
            return         


        command = event.arguments[0]

        if command.startswith('!cheap'):
            connection.privmsg(event.target, '<~Cameron> it\'s not expencive')
        elif 'shit' in command and 'bot' in command:
            connection.privmsg(event.target, 'Watch your tone, cuntboi')