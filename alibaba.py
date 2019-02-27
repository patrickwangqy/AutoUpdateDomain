# encoding: utf-8

"""
参考文档
https://help.aliyun.com/document_detail/29739.html?spm=a2c4g.11186623.6.615.68b67becl0YlBI

access key申请地址
https://usercenter.console.aliyun.com/#/manage/ak
"""

from lxml import html
import re
import time
import os
import json
import requests
import datetime
import random
import sys
import urllib
import hashlib
import hmac
import base64
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


def make_signature(request_str, access_key_secret):
    key = f'{access_key_secret}&'
    hashed = hmac.new(key.encode('utf-8'), request_str.encode('utf-8'), hashlib.sha1)
    return base64.b64encode(hashed.digest()).decode()


def urlencode(url):
    return urllib.parse.quote(url, safe='-_.~')


def make_get_url(request, access_key_secret):
    parameter_list = list(map(lambda key: '{key}={value}'.format(key=key, value=urlencode(request[key])), request))
    url = '/?' + '&'.join(parameter_list)
    parameter_list.sort()
    request_str = urlencode('/') + '&' + urlencode('&'.join(parameter_list))
    signature = make_signature('GET&' + request_str, access_key_secret)
    url = url + '&Signature=' + urlencode(signature)
    return 'http://alidns.aliyuncs.com' + url


def make_common_parameter_list(access_key_id):
    utc_time = datetime.datetime.utcnow()
    utc_str = utc_time.strftime('%Y-%m-%dT%H:%M:%SZ')
    rand = str(random.randint(0, sys.maxsize))
    request_parameter = {
        'Format': 'JSON',
        'Version': '2015-01-09',
        'AccessKeyId': access_key_id,
        'SignatureMethod': 'HMAC-SHA1',
        'Timestamp': utc_str,
        'SignatureVersion': '1.0',
        'SignatureNonce': rand,
    }
    return request_parameter


def get_record(rr, domain, access_key_id, access_key_secret):
    parameter_list = make_common_parameter_list(access_key_id)
    parameter_list['Action'] = 'DescribeDomainRecords'
    parameter_list['DomainName'] = domain
    url = make_get_url(parameter_list, access_key_secret)
    result = requests.get(url)
    result_json = json.loads(result.text)
    for record in result_json['DomainRecords']['Record']:
        if record['RR'] == rr:
            return record['RecordId'], record['Value']
    else:
        return ''


def update_recode(rr, domain, ip, access_key_id, access_key_secret):
    record_id, record_ip = get_record(rr, domain, access_key_id, access_key_secret)
    if record_ip == ip:
        print(f"{ip} for {rr}.{domain} is already latest")
        return
    parameter_list = make_common_parameter_list(access_key_id)
    parameter_list['Action'] = 'UpdateDomainRecord'
    parameter_list['RecordId'] = record_id
    parameter_list['RR'] = rr
    parameter_list['Type'] = 'A'
    parameter_list['Value'] = ip
    url = make_get_url(parameter_list, access_key_secret)
    result = requests.get(url)
    print(result)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--access_key_id", type=str, required=True)
    parser.add_argument("--access_key_secret", type=str, required=True)
    parser.add_argument("--domain", type=str, required=True)
    parser.add_argument("--rr", type=str, required=True)
    parser.add_argument("--sleep", type=int, default=60)
    args = parser.parse_args()
    while True:
        try:
            new_content = get_ip()
            print(f"Current Ip : {new_content}")
            update_recode(args.rr, args.domain, new_content, args.access_key_id, args.access_key_secret)
        except:
            pass
        time.sleep(60)


if __name__ == '__main__':
    main()
