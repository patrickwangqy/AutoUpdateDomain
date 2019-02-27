import requests
import time
import random
import hashlib
import hmac
import base64
import json
import urllib
from lxml import html
import re
import datetime
import argparse


def get_ip():
    session = requests.Session()
    session.trust_env = False
    response = session.get('http://2018.ip138.com/ic.asp')
    response.encoding = 'gbk'
    tree = html.fromstring(response.text)
    content = str(tree.xpath('//center/text()')[0])
    ip_pattern = r'\[(?P<ip>[0-9.]+)\]'
    pattern = re.compile(ip_pattern)
    return pattern.search(content).group('ip')


def generate_common_parameters():
    return {
        "Timestamp": str(int(time.time())),
        "Nonce": str(random.randint(0, 2**31-1)),
    }


def generate_request_parameters(parameters):
    return "&".join(map(lambda x: "=".join(x), sorted(list(parameters.items()), key=lambda x: x[0])))


def append_signature(parameters, secret_id, secret_key):
    parameters["SecretId"] = secret_id
    parameters["SignatureMethod"] = "HmacSHA256"
    signature_origin = "GETcns.api.qcloud.com/v2/index.php?" + generate_request_parameters(parameters)
    signature = base64.b64encode(hmac.new(secret_key.encode("utf-8"), signature_origin.encode("utf-8"), digestmod=hashlib.sha256).digest())
    parameters["Signature"] = urllib.parse.quote(signature.decode("utf-8"))


def get_record(domain, subdomain, secret_id, secret_key):
    parameters = generate_common_parameters()
    parameters["Action"] = "RecordList"
    parameters["domain"] = domain
    parameters["subDomain"] = subdomain
    append_signature(parameters, secret_id, secret_key)
    request_url = "https://cns.api.qcloud.com/v2/index.php?" + generate_request_parameters(parameters)
    response = requests.get(request_url)
    result = json.loads(response.content.decode("utf-8"))
    return result["data"]["records"][0]["value"], result["data"]["records"][0]["id"]


def update_record(domain, subdomain, record_id, new_ip, secret_id, secret_key):
    parameters = generate_common_parameters()
    parameters["Action"] = "RecordModify"
    parameters["domain"] = domain
    parameters["subDomain"] = subdomain
    parameters["recordId"] = str(record_id)
    parameters["recordType"] = "A"
    parameters["recordLine"] = "默认"
    parameters["value"] = new_ip
    append_signature(parameters, secret_id, secret_key)
    request_url = "https://cns.api.qcloud.com/v2/index.php?" + generate_request_parameters(parameters)
    response = requests.get(request_url)
    result = json.loads(response.content.decode("utf-8"))
    return result


def monitor_domain(domain, subdomain, secret_id, secret_key):
    print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    current_ip = get_ip()
    record_ip, record_id = get_record(domain, subdomain, secret_id, secret_key)
    print(f"current ip is {current_ip}")
    if current_ip != record_ip:
        print(f"record ip is {record_ip}, current ip and record ip are the different")
        print("updating record ip")
        result = update_record(domain, subdomain, record_id, current_ip, secret_id, secret_key)
        print(result["codeDesc"])
    else:
        print("current ip and record ip are the same")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--access_key_id", type=str, required=True)
    parser.add_argument("--access_key_secret", type=str, required=True)
    parser.add_argument("--domain", type=str, required=True)
    parser.add_argument("--rr", type=str, required=True)
    parser.add_argument("--sleep", type=int, default=60)
    args = parser.parse_args()
    while True:
        monitor_domain(args.domain, args.rr, args.access_key_id, args.access_key_secret)
        time.sleep(60)


if __name__ == '__main__':
    main()
