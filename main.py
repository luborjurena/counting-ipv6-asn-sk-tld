import csv
import pydig
import wget
import time
import pyasn
import subprocess
import os
import multiprocessing
from concurrent import futures as cf
from pathlib import Path

# Resolver configuration
resolver = pydig.Resolver(
     executable='/usr/bin/dig',
     nameservers=[
        '1.1.1.1',
        '1.0.0.1',
        '8.8.8.8',
        '8.8.4.4',
        '9.9.9.9'
     ],
     additional_args=[
         '+time=10',
         '+cd',
     ]
)

# Download domain list
wget.download('https://sk-nic.sk/subory/domains.txt', out='domains.txt')

# Download latest DB for pyasn
if os.path.exists('/usr/local/bin/pyasn_util_download.py'):
    subprocess.call(['/usr/local/bin/pyasn_util_download.py', '-6'], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
elif os.path.exists(str(Path.home()) + '/.local/bin/pyasn_util_download.py'):
    subprocess.call([str(Path.home()) + '/.local/bin/pyasn_util_download.py', '-6'], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
elif os.path.exists('./bin/pyasn_util_download.py'):
    subprocess.call(['./bin/pyasn_util_download.py', '-6'], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
else:
    raise Exception('Can\'t download pyasn database')

# # Convert DB and delete downloaded file
if os.path.exists('/usr/local/bin/pyasn_util_convert.py'):
    subprocess.run(['/usr/local/bin/pyasn_util_convert.py --single rib.*.bz2 asndb.dat'], shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    subprocess.run(['rm ' + os.getcwd() + '/rib.*.bz2'], shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
elif os.path.exists(str(Path.home()) + '/.local/bin/pyasn_util_convert.py'):
    subprocess.run([str(Path.home()) + '/.local/bin/pyasn_util_convert.py --single rib.*.bz2 asndb.dat'], shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    subprocess.run(['rm ' + os.getcwd() + '/rib.*.bz2'], shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
elif os.path.exists('./bin/pyasn_util_convert.py'):
    subprocess.run(['./bin/pyasn_util_convert.py --single rib.*.bz2 asndb.dat'], shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    subprocess.run(['rm ' + os.getcwd() + '/rib.*.bz2'], shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
else:
    raise Exception('Can\'t convert pyasn database')

# Parse domain.txt
with open('domains.txt') as csvfile:
    next(csvfile) # Skip header
    next(csvfile)
    next(csvfile)
    next(csvfile)
    next(csvfile)
    next(csvfile)
    next(csvfile)
    readCSV = csv.DictReader(csvfile, delimiter=';')
    domains = [row["domena"] for row in readCSV]

subprocess.run(['rm ' + os.getcwd() + '/domains.txt'], shell=True, check=True)

# Run dig asynchronously
resolved_domains = []
def dig(domain):
    query_type = 'AAAA'
    address = resolver.query(domain, query_type)
    resolved_domains.append([(domain), (address[0])])

with cf.ThreadPoolExecutor(max_workers=multiprocessing.cpu_count()/2) as pool: # Use 1/2 of available CPU cores
    jobs = (pool.submit(dig, domain) for domain in domains)
    for job in cf.as_completed(jobs):
        continue

asndb = pyasn.pyasn('asndb.dat')

all_asn = []
unique_asn = []
count_asn = []
pairing = {}

for _ in resolved_domains:
    try:
        result = asndb.lookup(_[1])
        result = str(result[0])
        all_asn.append(result)
        if not result in unique_asn:
            unique_asn.append(result)
    except ValueError:
        with open('error.log', 'a') as err_log:
            err_log.write('[ ' + time.strftime("%d.%m.%Y %H:%M:%S %Z") + ' ] ' + 'ValueError: ' + result + '\n')
        continue

for _ in unique_asn:
    count_asn.append(all_asn.count(_))

i = 0
for _ in unique_asn:
    pairing[_] = count_asn[i]
    i += 1

sort_pairs = sorted(pairing.items(), key=lambda x: x[1], reverse=True)

for asn, cnt in sort_pairs:
    print(f"ASN: {asn}, total domains: {cnt}")
