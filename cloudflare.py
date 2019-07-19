import requests
import datetime
from lxml import html
import re
import argparse
import time


def get_ip():
    session = requests.Session()
    session.trust_env = False
    response = session.get('http://2019.ip138.com/ic.asp')
    response.encoding = 'gbk'
    tree = html.fromstring(response.text)
    content = str(tree.xpath('//center/text()')[0])
    ip_pattern = r'\[(?P<ip>[0-9.]+)\]'
    pattern = re.compile(ip_pattern)
    return pattern.search(content).group('ip')


def get_record(domain, subdomain, zone_id, api_key):
    url = (f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?"
           f"type=A"
           f"&name={subdomain}.{domain}"
           f"&page=1"
           f"&per_page=20"
           f"&order=type"
           f"&direction=desc"
           f"&match=all")
    headers = {
        "Authorization": api_key,
        "Content-Type": "application/json"
    }
    response = requests.get(url, headers=headers)
    return response.json()["result"][0]["content"], response.json()["result"][0]["id"]


def update_record(domain, subdomain, record_id, current_ip, zone_id, api_key):
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}"
    headers = {
        "Authorization": api_key,
        "Content-Type": "application/json"
    }
    data = {
        "type":"A",
        "name": f"{subdomain}.{domain}",
        "content": current_ip
    }
    response = requests.put(url, headers=headers, json=data)
    return response.json()


def monitor_domain(domain, subdomain, secret_id, secret_key):
    print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    current_ip = get_ip()
    print(f"current ip is {current_ip}")
    record_ip, record_id = get_record(domain, subdomain, secret_id, secret_key)
    if current_ip != record_ip:
        print(f"record ip is {record_ip}, current ip and record ip are the different")
        print("updating record ip")
        result = update_record(domain, subdomain, record_id, current_ip, secret_id, secret_key)
        print(result["result"], result["success"])
    else:
        print("current ip and record ip are the same")


def main():
    zone_id = "6c6bb37fe75045385296fff8b86ae4dd"
    api_key = "Bearer HWIvzZoSYzw0VI8TSgU-fYBJxBQX8zRGPdtDuBiF"
    parser = argparse.ArgumentParser()
    parser.add_argument("--access_key_id", type=str, required=True)
    parser.add_argument("--access_key_secret", type=str, required=True)
    parser.add_argument("--domain", type=str, required=True)
    parser.add_argument("--rr", type=str, required=True)
    parser.add_argument("--sleep", type=int, default=60)
    args = parser.parse_args()
    while True:
        try:
            monitor_domain(args.domain, args.rr, args.access_key_id, f"Bearer {args.access_key_secret}")
            time.sleep(args.sleep)
        except Exception as e:
            print(e)


if __name__ == '__main__':
    main()
