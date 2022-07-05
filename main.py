import csv,pydig,wget,time,pyasn,subprocess,itertools,os,multiprocessing
from concurrent import futures as cf
from collections import Counter
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
         '+time=3',
         '+cd',
     ]
)

# Download domain list
wget.download('https://sk-nic.sk/subory/domains.txt', out='domains.txt')

# Download latest DB for pyasn
try:
    subprocess.call(['/usr/local/bin/pyasn_util_download.py', '-6'], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
except:
    subprocess.call([str(Path.home()) + '/.local/bin/pyasn_util_download.py', '-6'], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

# Convert DB and delete downloaded file
try:
    subprocess.run(['/usr/local/bin/pyasn_util_convert.py --single rib.*.bz2 asndb.dat'], shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    subprocess.run(['rm ' + os.getcwd() + '/rib.*.bz2'], shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
except:
    subprocess.run([str(Path.home()) + '/.local/bin/pyasn_util_convert.py --single rib.*.bz2 asndb.dat'], shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    subprocess.run(['rm ' + os.getcwd() + '/rib.*.bz2'], shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

# Parse domain list
domains = []
with open('domains.txt') as csvfile:
    next(csvfile) # Skip header
    next(csvfile)
    next(csvfile)
    next(csvfile)
    next(csvfile)
    next(csvfile)
    next(csvfile)
    readCSV = csv.DictReader(csvfile, delimiter=';')
    for row in readCSV:
        domains.append(row["domena"])

subprocess.run(['rm ' + os.getcwd() + '/domains.txt'], shell=True, check=True)

# Run dig asynchronously
dns =[]
def dig(domain):
    query_type = 'AAAA'
    ipv6 = resolver.query(domain, query_type)
    dns.append([(domain), (ipv6[0])])

with cf.ThreadPoolExecutor(max_workers=multiprocessing.cpu_count()) as pool:
    jobs = (pool.submit(dig, domain) for domain in domains)
    for job in cf.as_completed(jobs):
        continue

asndb = pyasn.pyasn('asndb.dat')

all_asn = []
unique_asn = []
count_asn = []
pairing = {}

for row in dns:
    try:
        result = asndb.lookup(row[1])
        result = result[0]
        result = str(result)
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
    print(asn, cnt)
