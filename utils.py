import requests

def parse_arraylyk_query(input):
    split = input.split(' ')
    index = 0
    if len(split[1:]) > 1 and split[-1].isdigit():
        index = (int(split[-1]) - 1) if int(split[-1]) > 0 else 0
        query = ' '.join(split[1:-1])
    else:
        query = ' '.join(split[1:])
    return index, query

def parse_arguments(input):
    processed_arguments = {}
    positional_arguments = []

    for i, j in enumerate(input):
        if j.startswith('-') and len(j) > 2:
            processed_arguments[j[:2]] = j[2:]
        elif j.startswith('@') and len(j) > 1:
            processed_arguments[j[:1]] = j[1:]
        elif j.startswith('-'):
            if i+1 < len(input) and not input[i+1].startswith('-'):
                processed_arguments[j[:2]] = input[i+1]
            else:
                processed_arguments[j[:2]] = True
        else:
            if (0 <= i-1) and i-1 < len(input):
                if not input[i-1].startswith('-'):
                    positional_arguments.append(j)

    return processed_arguments, positional_arguments

def uploadtext(text, ttl=3600):
    payload = {}
    payload['content'] = text
    payload['ttl'] = ttl
    r = requests.post('https://p.6core.net/', data=payload,timeout=5)
    return r.url