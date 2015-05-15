'''
Name: ips_inventory.py
Description: Cisco IPS Inventory Script
Requires: Python 'sys', 'paramiko', 'time', 'getpass' and 'os' libraries. 

Example Usage (Linux Command Line):

~ $ ips_inventory.py device_list.txt

Example Output:

IPS-DEVICE-1
 -IPS Version: 7.1(6)E4
 -Platform: ASA-SSM-20
 -Serial No.: DEF1234567
 -Signature Date: 2015-05-11
 -Signature Version: S867.0

IPS-DEVICE-2
 -IPS Version: 7.0(9)E4
 -Platform: AIM-IPS-K9
 -Serial No.: ABC1234567
 -Signature Date: 2015-05-12
 -Signature Version: S868.0
'''

import sys
import paramiko
import time
import getpass
import os

# Create dictionary of IPS information.
def create_ips_dict(ips_list, username, password):
  ips_dict = {}
  for host in ips_list:
    ips_dict[host] = {}  
    output = get_show_version(host, username, password)
    for line in output:
      if 'Platform:' in line:
        junk, platform = line.split()
        ips_dict[host]['Platform'] = platform
      if 'Serial Number:' in line:
        junk1, junk2, serial = line.split()
        ips_dict[host]['Serial No.'] = serial
      if 'Signature Update' in line:
        junk1, junk2, sigver, sigdate = line.split()
        ips_dict[host]['Signature Version'] = sigver
        ips_dict[host]['Signature Date'] = sigdate
      if 'Cisco Intrusion Prevention System' in line:
        junk, ver = line.split('Cisco Intrusion Prevention System, Version ')
        ips_dict[host]['IPS Version'] = ver.strip()
  return ips_dict

# Disable paging on IPS device.
def disable_paging(remote_conn, command="terminal length 0\n", delay=1):
  remote_conn.send("\n")
  remote_conn.send(command)
  time.sleep(delay)
  output = remote_conn.recv(10000)
  return output

# Connect to device via SSH and pull 'show version' info.
def get_show_version(host, username, password):
  remote_conn_pre = paramiko.SSHClient()
  remote_conn_pre.set_missing_host_key_policy(paramiko.AutoAddPolicy())
  remote_conn_pre.connect(host, username=username, password=password)
  remote_conn = remote_conn_pre.invoke_shell()
  output = disable_paging(remote_conn)
  remote_conn.send("\n")
  remote_conn.send("show version\n")
  time.sleep(1)
  output = remote_conn.recv(10000)
  output_list = output.split('\n')
  remote_conn_pre.close()
  return output_list  

# Print dictionary to file.
def print_dict_file(ips_dict):
  output_file = open('ips_inventory_output.txt', 'w')
  for k, v in sorted(ips_dict.items()):
    print >> output_file, k.upper()  
    for k1, v1 in sorted(v.items()):
      print >> output_file, " -%s: %s" % (k1, v1)
    print >> output_file, "\n"  

# Print dictionary to standard output.
def print_dict_stdout(ips_dict):
  for k, v in sorted(ips_dict.items()):
    print k.upper()
    for k1, v1 in sorted(v.items()):
      print " -%s: %s" % (k1, v1)
    print "\n"

# Create Python list from user specified input file.
def create_ips_list(f):
  ips_list = f.readlines()
  new_list = []
  for i in ips_list:
    new_list.append(i.strip('\n'))
  return new_list  

# Main Program
def main():

  if len(sys.argv) == 2:
    f = open(sys.argv[1])
    ips_list = create_ips_list(f)	
    f.close()
    
    print "###################################"
    print "# IPS Device Info Collection Tool #"
    print "###################################\n"
    username = raw_input("Please enter IPS username: ") 
    password = getpass.getpass("Please enter IPS password: ")

    ips_dict = create_ips_dict(ips_list, username, password)  
    print_dict_file(ips_dict)

  else:
    print "ERROR: Missing device list file.  Please include the full path of the IPS device list after the script name."
 
if __name__ == '__main__':
  try:
    main()
  except KeyboardInterrupt:
    print "/n"
    print "ERROR: Keyboard Interrupt"
    try:
      sys.exit(0)
    except SystemExit:
      os._exit(0)
