#!/usr/bin/python

import argparse
import subprocess
import requests
import os

# Edit these with your values
username='lakshmankumar'
hostname='lakshmankumar.ddns.net'
interface_to_update='eth2'
passwordfile=os.path.join(os.path.expanduser("~"),".noippassword")

password=None
url='https://dynupdate.no-ip.com/nic/update'

def get_ip_of_interface(interface):
  child=subprocess.Popen(["/sbin/ip","-4","addr","show",interface],stdout=subprocess.PIPE)
  (output,err)=child.communicate()
  ret=child.wait()
  if ret != 0:
    raise Exception("/sbin/ip didn't return 0")
  for line in output.splitlines():
    if "inet" in line:
      ip_mask=line.split()[1]
      return ip_mask[:-3]

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

  ip=get_ip_of_interface(interface_to_update)
  update_ip(ip)


if __name__ == '__main__':
  main()

