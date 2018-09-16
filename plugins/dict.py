import baseplugin
import utils

import json
import sqlite3
import requests
import urllib

import pprint

class Plugin_dict(baseplugin.BasePlugin):
    def on_pubmsg(self, connection, event, bot):
        if not event.arguments[0].startswith('{prefix}{command}'.format(prefix=self.commandprefix, command=self.command)):
            return
        input = event.arguments[0]
        if not 'dict_app_id' in self.bot.botconfig or not 'dict_app_key' in self.bot.botconfig:
            connection.privmsg(event.target, 'api not setup')
            return
        if len(input.split(' ')) > 1:
            item, query = utils.parse_arraylyk_query(input)
            dict_entry = None
            try:
                conn = sqlite3.connect(self.bot.botconfig['sqdatabase'])
                cursor = conn.execute('SELECT json FROM `oxford_dict` WHERE word = ?', (query,))
                data = cursor.fetchone()
                if data:
                    dict_entry = json.loads(data[0])
                    print('found data db')
                else:
                    dict_entry = self.get_dictionary_entry(query)
                    print('querying oxford')
                    if dict_entry:
                        conn.execute('INSERT INTO `oxford_dict` (word, json) VALUES (?, ?)', (query, json.dumps(dict_entry),))
                        conn.commit()
                        print('added to db')
            except:
                raise
            if dict_entry:
                to_send_array = []
                for i in dict_entry['results']:
                    for j in i['lexicalEntries']:
                        for k in j['entries']:
                            for l in k['senses']:
                                if 'crossReferences' in l:
                                    to_send_array.append('{marker}, see also {crossid}'.format(marker=l['crossReferenceMarkers'][0],crossid=l['crossReferences'][0]['id']))
                                if 'definitions' not in l:
                                    continue
                                for m in l['definitions']:
                                    to_send_array.append('{lexicalCategory}, {definition}'.format(lexicalCategory=j['lexicalCategory'].lower(),definition=m))
                if len(to_send_array) > 0:
                    if item+1 > len(to_send_array):
                        print(5435345)
                        connection.privmsg(event.target, 'out of range')
                        return
                    connection.privmsg(event.target, '{word}[{index}/{len}] {value}'.format(word=query,index=item+1,len=len(to_send_array),value=to_send_array[item]))
            else:
                connection.privmsg(event.target, 'word not found over')
        else:
            connection.privmsg(event.target, 'what')

    def get_dictionary_entry(self, word):
        headers = {
            'Accept': 'application/json',
            'app_id': self.bot.botconfig['dict_app_id'],
            'app_key': self.bot.botconfig['dict_app_key']
        }
        r = requests.get('https://od-api.oxforddictionaries.com/api/v1/entries/en/'+urllib.parse.quote(word.lower(),safe=''), headers=headers,timeout=5)
        if int(r.status_code) != 200:
            return None
        return r.json()