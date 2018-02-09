import pydle
import getdns
import argparse
import shlex
import ipaddress
import time
import pprint
import requests
import configparser
import base64
import datetime
import binascii
import sqlite3

class BanaanBot(pydle.Client):
    def on_connect(self):
        super().on_connect()
        self.rawmsg('NICKSERV', 'IDENTIFY %s' % config['Bot']['nickserv'])
        for i in config['Bot']['channels'].split(','):
            self.join(i)
        print('connected')
    def on_unknown(self, message):
        super().on_unknown(message)
        #print(message)
    def on_raw(self, message):
        super().on_raw(message)
        print('RECEIVED: ' + str(message),end='')
        if '464' in str(message).split(" "):
            self.rawmsg('PASS', '{}'.format(config['Bot']['pass']))
    def on_channel_message(self, target, by, message):
        super().on_channel_message(target, by, message)
    def rawmsg(self, command, *args, **kwargs):
        if command.startswith('WHOIS'):
            print('NOT SENT: ' + str(command) + str(args) + str(kwargs))
            return
        print('SENT: ' + str(command) + str(args) + str(kwargs))
        super().rawmsg(command, *args, **kwargs)
    def on_message(self, target, by, message):
        if by == 'Telegram':
            self.on_message(target, 'Banaan', message[(message.index(':')+1):].strip())
            return
        super().on_message(target, by, message)

        if message.startswith('!'):
            if message.find('=') > 0:
                processQuoteAdd(self, target, by, message)
            elif message.find('?') > 0:
                processQuoteGet(self, target, by, message)
            elif message.find('++') > 0:
                processKarmaPlus(self, target, by, message)
                print('plus ', message[1:message.find('++')])
            elif message.find('--') > 0:
                processKarmaMinus(self, target, by, message)
                print('min ', message[1:message.find('--')])

        if message.startswith('!dig'):
            try:
                processDig(self, target, by, message)
            except:
                raise
        elif message.startswith('!cheap'):
            self.message(target, "<~Cameron> it's not expencive")

def getDatabase():
    conn = sqlite3.connect('banaan.db')
    return conn

def processQuoteAdd(self, target, by, message):
    index = message.find('=')
    if index > 0:
        name = message[1:index].strip().lower()
        quote = message[index+1:].strip()
        if name and quote:
            try:
                conn = getDatabase()
                conn.execute('INSERT INTO quotes (name, quote) VALUES (?, ?)', (name, quote,))
                conn.commit()
            except:
                raise
            finally:
                conn.close()

def processKarmaPlus(self, target, by, message):
    index = message.find('++')
    if index > 0:
        name = message[1:index].strip().lower()
        if name:
            try:
                karma = None
                conn = getDatabase()
                cursor = conn.execute('SELECT id, karma FROM karma WHERE name = ?', (name,))
                data = cursor.fetchone()
                if data:
                    id, karma = data
                    karma = karma + 1
                    conn.execute('UPDATE karma SET karma = ? WHERE id = ?', (karma, id))
                    conn.commit()
                else:
                    karma = 1
                    conn.execute('INSERT INTO karma (name, karma) VALUES (?, ?)', (name, karma))
                    conn.commit()
                self.message(target, 'karma of {} is now {}'.format(name, karma))
            except:
                raise
            finally:
                conn.close()

def processKarmaMinus(self, target, by, message):
    index = message.find('--')
    if index > 0:
        name = message[1:index].strip().lower()
        if name:
            try:
                karma = None
                conn = getDatabase()
                cursor = conn.execute('SELECT id, karma FROM karma WHERE name = ?', (name,))
                data = cursor.fetchone()
                if data:
                    id, karma = data
                    karma = karma - 1
                    conn.execute('UPDATE karma SET karma = ? WHERE id = ?', (karma, id))
                    conn.commit()
                else:
                    karma = -1
                    conn.execute('INSERT INTO karma (name, karma) VALUES (?, ?)', (name, karma))
                    conn.commit()
                self.message(target, 'karma of {} is now {}'.format(name, karma))
            except:
                raise
            finally:
                conn.close()

def processQuoteGet(self, target, by, message):
    index = message.find('?')
    if index > 0:
        name = message[1:index].strip().lower()
        if name:
            try:
                conn = getDatabase()
                cursor = conn.execute('SELECT * FROM quotes WHERE name = ?', (name,))
                data = cursor.fetchall()
                if data:
                    if len(data) > 1:
                        tosend = ''
                        for i in data:
                            id, name, quote = i
                            tosend = tosend + quote + ' ... '
                        self.message(target, tosend[:-5])
                    else:
                        id, name, quote = data[0]
                        self.message(target, quote)

                else:
                    self.message(target, 'kein quotes')
            except:
                raise
            finally:
                conn.close()

def parseArguments(arguments):
    processed_arguments = dict()
    positional_arguments = list()

    for i, j in enumerate(arguments):
        if j.startswith('-') and len(j) > 2:
            processed_arguments[j[:2]] = j[2:]
        elif j.startswith('@') and len(j) > 1:
            processed_arguments[j[:1]] = j[1:]
        elif j.startswith('-'):
            if i+1 < len(arguments) and not arguments[i+1].startswith('-'):
                processed_arguments[j[:2]] = arguments[i+1] 
            else:
                processed_arguments[j[:2]] = True
        else:
            if (0 <= i-1) and i-1 < len(arguments):
                if not arguments[i-1].startswith('-'):
                    positional_arguments.append(j)

    return processed_arguments, positional_arguments

def processDig(self, target, by, message):
    split = shlex.split(message, posix=True)
    if len(split) <= 1:
        raise ValueError('boi why u no give me something to process')
    server, qtype, query, do_reverse, debug = [None for _ in range(5)]
    args, pargs = parseArguments(split)
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
        query = ipaddress.ip_address(query).reverse_pointer
        qtype = 'PTR'
    results, rawresults, ctx= querydns(query, qtype, server, do_reverse)
    if debug:
        print('debug')
        pp = pprint.PrettyPrinter(indent=4)
        pp.pprint(rawresults.replies_full)
        toupload = pp.pformat(ctx.get_api_information()) + "\n" + pp.pformat(rawresults.replies_full)
        self.message(target, uploadtext(toupload))
        return
    if results['status'] == getdns.RESPSTATUS_GOOD:
        if results['header']['rcode'] == getdns.RCODE_NOERROR:
            toupload = ""
            for i in results['answers']:
                if len(results['answers']) > 3:
                    toupload = toupload + i + "\n"
                else:
                    self.message(target, i)                
            if toupload:
                self.message(target, uploadtext(toupload))
        else:
            self.message(target, 'rcode: {0}'.format(results['header']['rcode']))
    elif results['status'] == getdns.RESPSTATUS_NO_NAME:
        #self.message(target, "{0}: no name".format(results['question']['qname']))
        for i in results['answers']:
            self.message(target, i)
    elif results['status'] == getdns.RESPSTATUS_ALL_TIMEOUT:
        self.message(target, "timeout")
    else:
        self.message(target, "unknown")

def querydns(query, qtype, server, do_reverse):
    pp = pprint.PrettyPrinter(indent=4)
    ctx = getdns.Context(False)

    if not query:
        raise ValueError('You forgot to fill in the thing to be queried boi')
    if not qtype:
        qtype = 'A'
    if server:
        try:
            server = ipaddress.ip_address(server)
            ctx.resolution_type = getdns.RESOLUTION_STUB
            ctx.upstream_recursive_servers = [{'address_data': '%s' % server, 'address_type': 'IPv%s' % server.version}]
        except ValueError: 
            results = ctx.general(server, getdns.RRTYPE_A, extensions = { "return_both_v4_and_v6" : getdns.EXTENSION_TRUE })
            if results.status == getdns.RESPSTATUS_GOOD:
                ctx.resolution_type = getdns.RESOLUTION_STUB
                ctx.upstream_recursive_servers = results.just_address_answers
    if not do_reverse:
        do_reverse = False
    try:
        rrtype = getattr(getdns, 'RRTYPE_%s' % qtype.upper())
    except AttributeError:
        raise ValueError('qtype no existent')

    results = ctx.general(query, rrtype)
    results_to_return = {}
    results_to_return['answers'] = []
    results_to_return['status'] = results.status
    if results.status == getdns.RESPSTATUS_GOOD:
        for reply in results.replies_tree:
            for i in reply:
                if not (i == 'answer' or i == 'additional'):
                    continue
                results_to_return['header'] = reply['header']
                results_to_return['question'] = reply['question']
                results_to_return['authority'] = reply['authority']
                for answer in reply[i]:
                    if answer['type'] == getdns.RRTYPE_SOA:
                        results_to_return['answers'].append('{0}\t{1}\tIN\tSOA\t{2} {3} {4} {5} {6} {7} {8}'
                            .format(
                                answer['name']
                                ,answer['ttl']
                                ,answer['rdata']['mname']
                                ,answer['rdata']['rname']
                                ,answer['rdata']['serial']
                                ,answer['rdata']['refresh']
                                ,answer['rdata']['retry']
                                ,answer['rdata']['expire']
                                ,answer['rdata']['minimum']))
                    elif answer['type'] == getdns.RRTYPE_NS:
                        results_to_return['answers'].append('{0}\t{1}\tIN\tNS\t{2}'
                            .format(
                                answer['name']
                                ,answer['ttl']
                                ,answer['rdata']['nsdname']
                                ))
                    elif answer['type'] == getdns.RRTYPE_A:
                        results_to_return['answers'].append('{0}\t{1}\tIN\tA\t{2}'
                            .format(
                                answer['name']
                                ,answer['ttl']
                                ,ipaddress.ip_address(bytes(answer['rdata']['ipv4_address']))
                                ))
                    elif answer['type'] == getdns.RRTYPE_AAAA:
                        results_to_return['answers'].append('{0}\t{1}\tIN\tAAAA\t{2}'
                            .format(
                                answer['name']
                                ,answer['ttl']
                                ,ipaddress.ip_address(bytes(answer['rdata']['ipv6_address']))
                                ))
                    elif answer['type'] == getdns.RRTYPE_MX:
                        results_to_return['answers'].append('{0}\t{1}\tIN\tMX\t{2} {3}'
                            .format(
                                answer['name']
                                ,answer['ttl']
                                ,answer['rdata']['preference']
                                ,answer['rdata']['exchange']
                                ))
                    elif answer['type'] == getdns.RRTYPE_TXT:
                        results_to_return['answers']. append('{0}\t{1}\tIN\tTXT\t{2}'
                            .format(
                                answer['name']
                                ,answer['ttl']
                                ,answer['rdata']['txt_strings']
                                ))
                    elif answer['type'] == getdns.RRTYPE_CAA:
                        results_to_return['answers']. append('{0}\t{1}\tIN\tCAA\t{2} {3} {4}'
                            .format(
                                answer['name']
                                ,answer['ttl']
                                ,answer['rdata']['flags']
                                ,answer['rdata']['tag']
                                ,answer['rdata']['value']
                                ))
                    elif answer['type'] == getdns.RRTYPE_OPT:
                        continue
                    elif answer['type'] == getdns.RRTYPE_RRSIG:
                        results_to_return['answers']. append('{0}\t{1}\tIN\tRRSIG\t{2} {3} {4} {5} {6} {7} {8} {9} {10}'
                            .format(
                                answer['name']
                                ,answer['ttl']
                                ,answer['rdata']['type_covered']
                                ,answer['rdata']['algorithm']
                                ,answer['rdata']['labels']
                                ,answer['rdata']['original_ttl']
                                ,datetime.datetime.utcfromtimestamp(answer['rdata']['signature_expiration']).strftime('%Y%m%d%H%M%S')
                                ,datetime.datetime.utcfromtimestamp(answer['rdata']['signature_inception']).strftime('%Y%m%d%H%M%S')
                                ,answer['rdata']['key_tag']
                                ,answer['rdata']['signers_name']
                                ,base64.b64encode(answer['rdata']['signature']).decode('utf-8')
                                ))
                    elif answer['type'] == getdns.RRTYPE_DNSKEY:
                        results_to_return['answers']. append('{0}\t{1}\tIN\tDNSKEY\t{2} {3} {4}'
                            .format(
                                answer['name']
                                ,answer['ttl']
                                ,answer['rdata']['flags']
                                ,answer['rdata']['protocol']
                                ,answer['rdata']['algorithm']
                                ))
                    elif answer['type'] == getdns.RRTYPE_NSEC3PARAM:
                        results_to_return['answers']. append('{0}\t{1}\tIN\tNSEC3PARAM\t{2} {3} {4} {5}'
                            .format(
                                answer['name']
                                ,answer['ttl']
                                ,answer['rdata']['hash_algorithm']
                                ,answer['rdata']['flags']
                                ,answer['rdata']['iterations']
                                ,binascii.hexlify(answer['rdata']['salt']).decode('utf-8').upper()
                                ))
                    elif answer['type'] == getdns.RRTYPE_PTR:
                        results_to_return['answers']. append('{0}\t{1}\tIN\tPTR\t{2}'
                            .format(
                                answer['name']
                                ,answer['ttl']
                                ,answer['rdata']['ptrdname']
                                ))
                    else:
                        results_to_return['answers'].append('Found type {0}, cannot process just now.'
                            .format(
                                answer['type']
                                ))
                        pp.pprint(answer)
    else:
        for reply in results.replies_tree:
            results_to_return['question'] = reply['question']
            results_to_return['authority'] = reply['authority']
            if 'authority' in reply:
                for answer in reply['authority']:
                    if answer['type'] == getdns.RRTYPE_SOA:
                        results_to_return['answers'].append('{0}\t{1}\tIN\tSOA\t{2} {3} {4} {5} {6} {7} {8}'
                            .format(
                                answer['name']
                                ,answer['ttl']
                                ,answer['rdata']['mname']
                                ,answer['rdata']['rname']
                                ,answer['rdata']['serial']
                                ,answer['rdata']['refresh']
                                ,answer['rdata']['retry']
                                ,answer['rdata']['expire']
                                ,answer['rdata']['minimum']))
    return results_to_return, results, ctx

def uploadtext(text):
    payload = {}
    payload['content'] = text
    payload['ttl'] = 3600
    r = requests.post('https://p.6core.net/', data = payload)
    return r.url


config = configparser.ConfigParser()
config.read('banaan.ini')
if 'Bot' in config:
    client = BanaanBot(config['Bot']['nickname'], realname=config['Bot']['realname'])
    client.connect(config['Bot']['server'], config['Bot']['port'], tls=True, tls_verify=False)
    try:
        client.handle_forever()
    except KeyboardInterrupt:
        print("keyboard interrupt")
        client.disconnect()
        client.raw('QUIT :bepis')
        raise
