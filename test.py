import requests

headers = {'User-Agent': 'Mozilla/5.0'}
url = 'https://sk-nic.sk/subory/domains.txt'

r = requests.get(url, headers=headers)
#print(r.content)

with open('domains.txt', 'wb') as fh:
    fh.write(r.content)
