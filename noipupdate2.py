#!/usr/bin/python

import argparse
import subprocess
import requests
import os
import re

from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests.packages.urllib3.exceptions import InsecurePlatformWarning
from requests.packages.urllib3.exceptions import SNIMissingWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
requests.packages.urllib3.disable_warnings(InsecurePlatformWarning)
requests.packages.urllib3.disable_warnings(SNIMissingWarning)

# Edit these with your values
username='lakshmankumar'
hostname='lkwinhost.ddns.net'
actual_long_host_to_update='usmovdlnara002n.eng.timetra.com'
passwordfile=os.path.join(os.path.expanduser("~"),".noippassword")

password=None
url='https://dynupdate.no-ip.com/nic/update'

def get_ip_of_actual_host(actual_host):
  child=subprocess.Popen(["dig",actual_host],stdout=subprocess.PIPE)
  (output,err)=child.communicate()
  ret=child.wait()
  if ret != 0:
    raise Exception("dig didn't return 0")
  status_ok = 0
  match = re.compile("IN\s+A\s+(\d+\.\d+\.\d+\.\d+)")
  for line in output.splitlines():
    if "status: NOERROR" in line:
      status_ok = 1
    if status_ok and match.search(line):
      a = match.search(line)
      return a.group(1)
  return None

def save_password(password):
  # Simple encryption .. We can as well save in plain-text
  # The point is not to keep this safe from eavesdropping, but simply to not appear in some cat
  # other program's find etc..
  fd=open(passwordfile,"w")
  for i in password:
    fd.write(chr(ord(i)^0xaa))
  fd.close()

def load_password():
  fd=open(passwordfile,"r")
  a=fd.read()
  fd.close()
  password=""
  for i in a:
    password += chr(ord(i)^0xaa)
  return password

def update_ip(ip):
  payload={'myip':ip,'hostname':hostname}
  print "payload:%s"%payload
  result=requests.get(url,params=payload,auth=(username,password),verify=False)
  if not result.ok:
    print "Sorry.. didn't get a good result:%s"%result.text
  else:
    print "updated:%s"%result.text

def main():
  global password

  parser = argparse.ArgumentParser()
  parser.add_argument("-a","--askpassword",  help="ask password from user", action="store_true")
  parser.add_argument("-s","--savepassword", help="save password for later use", action="store_true")

  args = parser.parse_args()

  if args.askpassword:
    import getpass
    password=getpass.getpass("Password for user:%s in noip.com:"%username)
    if args.savepassword:
      save_password(password)
  else:
    password=load_password()

  ip=get_ip_of_actual_host(actual_long_host_to_update)
  if (ip):
    update_ip(ip)
  else:
    print "didnt get ip"


if __name__ == '__main__':
  main()

