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

class Plugin_dig(baseplugin.BasePlugin):
    def on_pubmsg(self, connection, event):
        if not event.arguments[0].startswith('{prefix}{command}'.format(prefix=self.commandprefix, command=self.command)):
            return
        input = event.arguments[0]
        split = shlex.split(input, posix=True)
        if not len(split) > 1:
            connection.privmsg(event.target, 'invalid input')
            return
        server, qtype, query, do_reverse, debug = ('1.1.1.1', None, None, False, False)
        args, pargs = utils.parse_arguments(split)
        for i,j in args.items():
            if i == '-t':
                qtype = j
            elif i == '-q':
                query = j
            elif i == '-x':
                do_reverse = True
            elif i == '@':
                server = j
            elif i == '-d':
                debug = True
        for i in pargs:
            if not query:
                query = i
            elif not qtype:
                qtype = i
        if do_reverse:
            query = dns.reversename.from_address(query)
            qtype = 'PTR'
        resolver = dns.resolver.Resolver(configure=False)
        resolver.lifetime = 2
        resolver.nameservers = [server]
        try:
            answer = resolver.query(query, qtype if qtype else 'A')
            if answer.response.rcode() == dns.rcode.NOERROR:
                split = answer.rrset.to_text().split('\n')
                for i in split:
                    connection.privmsg(event.target, i)
            else:
                connection.privmsg(event.target, dns.rcode.to_text(answer.response.rcode()))
        except Exception as e:
            connection.privmsg(event.target, str(e))
