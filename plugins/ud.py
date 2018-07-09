import baseplugin
import utils

import requests

import pprint

class Plugin_ud(baseplugin.BasePlugin):
    def on_pubmsg(self, connection, event):
        if not event.arguments[0].startswith('{prefix}{command}'.format(prefix=self.commandprefix, command=self.command)):
            return
        input = event.arguments[0]
        if len(input.split(' ')) > 1:
            item, query = utils.parse_arraylyk_query(input)

            params = {
                'term': query
            }
            r = requests.get('https://api.urbandictionary.com/v0/define', params=params, timeout=5)
            if r.status_code == 200:
                data = r.json()
                if len(data['list']) > 0:
                    if item + 1 > len(data['list']):
                        connection.privmsg(event.target, 'out of range')
                        return
                    connection.privmsg(event.target, '{query}[{item}/{len}] {data}'.format(
                        query=query
                        , item=item + 1
                        , len=len(data['list'])
                        , data=data['list'][item]['definition'].replace('\n', ' ').replace('\r', ' ').replace('  ', '')
                    )[:256])
                else:
                    connection.privmsg(event.target, 'cannot find word')