## Cisco IPS Inventory Auto

### Introduction

Cisco IPS Automated Inventory / Reporting Tool.  This script will parse a list of IPS device names and generate a report on each device.  It will also check the Cisco RSS Feed to identify if a new security bulletin has been released.

### Installation Notes / Prerequisites

**Script written in Python2**

### Usage
```
ips_inventory_auto.py -l 'PATH TO DEVICE LIST' -u 'USERNAME' -p 'PASSWORD' -e 'EMAILFROM' 'EMAILTO' -s 'SMTP_RELAY'
```

### Sample Output

*** NEW CISCO IPS BULLETIN RELEASED ***
Cisco IPS Threat Defense Bulletins:08-JUN-2016
http://tools.cisco.com/security/center/viewBulletin.x?bId=743&year=2016&vs_f=Cisco%20IPS%20Threat%20Defense%20Bulletins&vs_cat=Security%20Intelligence&vs_type=RSS&vs_p=Cisco%20IPS%20Threat%20Defense%20Bulletins:08-JUN-2016&vs_k=1

US-SSM-EDG1-PRI  
\-IPS Version: 7.3(5)E4  
\-Platform: ASA5545-IPS  
\-Serial No.: FCH123456PE  
\-Signature Date: 2016-06-06  
\-Signature Version: S924.0

US-SENSOR-01    
\-IPS Version: 7.0(9)E4  
\-Platform: AIM-IPS-K9  
\-Serial No.: FOC123456KJ  
\-Signature Date: 2016-05-31  
\-Signature Version: S923.0
