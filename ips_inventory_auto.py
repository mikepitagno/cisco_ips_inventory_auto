'''
Cisco IPS Inventory Status Tool

Example Usage:

~/IPS_INVENTORY/ips_inventory_auto.py -l ~/IPS_INVENTORY/ips_device_list.txt -u <USERNAME> -p <PASSWORD> -e <EMAILFROM> <EMAILTO> -s <SMTP_RELAY>

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

#!/usr/bin/env python

import sys
import paramiko
import time
import os
import shutil
import yaml
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import feedparser
import argparse
from os.path import expanduser

# Create Python list from user specified input file
def create_ips_list(f):
  ips_list = f.readlines()
  new_list = []
  for i in ips_list:
    new_list.append(i.strip('\n'))
  return new_list  

# Create dictionary of IPS information
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

# Disable paging on IPS device
def disable_paging(remote_conn, command="terminal length 0\n", delay=1):
  remote_conn.send("\n")
  remote_conn.send(command)
  time.sleep(delay)
  output = remote_conn.recv(10000)
  return output

# Connect to device via SSH and pull 'show version' info
def get_show_version(host, username, password):
  remote_conn_pre = paramiko.SSHClient()
  remote_conn_pre.set_missing_host_key_policy(paramiko.AutoAddPolicy())
  remote_conn_pre.connect(host, username=username, password=password)
  remote_conn = remote_conn_pre.invoke_shell()
  output = disable_paging(remote_conn)
  remote_conn.send("\n")
  remote_conn.send("show version\n")
  time.sleep(2)
  output = remote_conn.recv(10000)
  output_list = output.split('\n')
  remote_conn_pre.close()
  return output_list  

# Load IPS dictionary into a formatted string 
def load_dict_into_string(ips_dict):
  output_file = ''
  for k, v in sorted(ips_dict.items()):
    output_file = output_file + '\n'
    output_file = output_file + k.upper() + '\n'
    for k1, v1 in sorted(v.items()):
      output_file = output_file + "-%s: %s" % (k1, v1) + '\n'
  return output_file

# Pull latest Cisco IPS bulletin from RSS feed compare to latest saved 
def cisco_rss_info(rss_path):
  f = file(rss_path, "r")
  rss_old = f.read().decode('utf8')
  f.close()
  d = feedparser.parse('https://tools.cisco.com/security/center/activeUpdateBulletin_20.xml')
  rss = d['entries'][0]['title'] + "\n" + d.entries[0]['link'] + "\n"
  if rss == rss_old: 
    status = True
  else:
    status = False
  with open(rss_path, "wb") as f:
    f.write(rss.encode("UTF-8"))
    f.close()
  return rss, status

# Email Cisco IPS bulletin and string formatted IPS dictionary
def email_dict_new(ips_dict, email_sender, email_receiver, smtp_server, bulletin, status):
  alert = '*** NEW CISCO IPS BULLETIN RELEASED ***\n'
  if status == True:
    body = bulletin + "\n" + load_dict_into_string(ips_dict) + "\n"
  else:
    body = alert + bulletin + "\n" + load_dict_into_string(ips_dict) + "\n"
  msg = MIMEText(body)
  msg['Subject'] = "IPS Status Report"
  msg['From'] = email_sender
  msg['To'] = email_receiver
  s = smtplib.SMTP(smtp_server)
  s.sendmail(email_sender, [email_receiver], msg.as_string())
  s.quit()

# Print dictionary to standard output
def print_dict_stdout(ips_dict):
  for k, v in sorted(ips_dict.items()):
    print k.upper()
    for k1, v1 in sorted(v.items()):
      print " -%s: %s" % (k1, v1)
    print "\n"

# Print dictionary to HTML file
def print_dict_html(ips_dict, html_path):
  output_file = open(html_path, 'w')
  print >> output_file, "<head>"
  print >> output_file, '  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />'
  print >> output_file, "  <title>IPS Inventory Info</title>"
  print >> output_file, '  <style type="text/css">'  
  print >> output_file, "    #container {"
  print >> output_file, "      width: 780px;"
  print >> output_file, "      background: #FFFFFF;"
  print >> output_file, "      margin: 0 auto;"
  print >> output_file, "      border: 1px solid #000000;"
  print >> output_file, "      text-align: left;"
  print >> output_file, "      font-size: 0.75em;"
  print >> output_file, "    }"
  print >> output_file, "    #mainContent {"
  print >> output_file, "      margin: 0 0 0 0px;"
  print >> output_file, "      padding: 0 20px 20px 20px;"
  print >> output_file, "      line-height: 0.5;"
  print >> output_file, "    }"
  print >> output_file, "  </style>"
  print >> output_file, "</head>"
  print >> output_file, "<body>"
  print >> output_file, "  <!--container div tag-->"
  print >> output_file, '  <div id="container">'
  print >> output_file, "    <!--mainContent div tag-->"
  print >> output_file, '    <div id="mainContent">'
  print >> output_file, "      <h1>IPS Inventory Info</h1>"
  print >> output_file, "      <p>Data collected on %s.</p>" % (time.strftime("%A %b %d, %Y @%X"))
  print >> output_file, "      <BR>"
  for k, v in sorted(ips_dict.items()):
    print >> output_file, "<h4>%s</h4>" % k.upper()
    for k1, v1 in sorted(v.items()):
      print >> output_file, "<p> -%s: %s</p>" % (k1, v1)
    print >> output_file, "<BR>"
  print >> output_file, "      </div>"
  print >> output_file, "  </div>"
  print >> output_file, "</body>"

# Archive old HTML inventory file
def archive(html_path, archive_dir):
  archive_file = os.path.join(archive_dir, os.path.basename(html_path) + time.strftime("-%Y%m%d-%H%M%S"))
  if os.path.exists(html_path) == True:
    shutil.copy2(html_path, archive_file)

# Main Program
def main():

# Command line arguments
  parser = argparse.ArgumentParser(description='CLI arguments for IPS Inventory')
  parser.add_argument('-l','--device_list',type=argparse.FileType('r'),help='Device List',required=True)
  parser.add_argument('-u','--username',help='Target User',required=False,default='admin')
  parser.add_argument('-p','--password',help='Target Password',required=True)
  parser.add_argument('-e','--email',metavar=("EMAILFROM", "EMAILTO"),help='Email From / Email To',required=False,nargs=2)
  parser.add_argument('-s','--smtp_server',help='SMTP Relay',required=True)
  args = parser.parse_args()

# Create Python list from IPS device list  
  device_list = args.device_list 
  ips_list = create_ips_list(device_list)
  device_list.close()

# Create additional variabled from CLI args  
  username = args.username
  password = args.password
  email_sender = args.email[0]
  email_receiver = args.email[1]
  smtp_server = args.smtp_server

# Assign user's home directory to variable
  home = expanduser("~")

# Create IPS dictionary  
  ips_dict = create_ips_dict(ips_list, username, password)  

# Get latest Cisco IPS bulletin and confirm if script has seen it before
  rss_path = home + '/IPS_INVENTORY/rss_old.txt'
  bulletin, status = cisco_rss_info(rss_path)

# Email dictionary
  email_dict_new(ips_dict, email_sender, email_receiver, smtp_server, bulletin, status)

#  Uncomment following line to print dictionary to standard output
#  print_dict_stdout(ips_dict)

#  Uncomment following 4 lines to have inventory info written to HTML file; Archive old file.
#  html_path = home + '/IPS_INVENTORY/ips_inventory.html' 
#  print_dict_html(ips_dict, html_path)
#  archive_dir = home + '/IPS_INVENTORY/archive'
#  archive(html_path, archive_dir)

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
