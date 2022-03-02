import requests
import json
import time
import os
import csv
import glob
import operator
import socket
import warnings
import tenbCore as tc
from datetime import datetime
warnings.filterwarnings("ignore")

'''
# list scans from tenable.ep
api_keys = tc.read_keys("../io_keys.json","ep")
results_json=tc.list_scans(api_keys)
print(results_json)


# get vuln filters from tenable.ep
api_keys = tc.read_keys("../io_keys.json","ep")
results_json=tc.get_vuln_filters(api_keys)
print(results_json)


# download vuln workbench from tenable.ep
api_keys = tc.read_keys("../io_keys.json","ep")
filter={
"filter.0.filter":"host.target",
"filter.0.quality":"eq",
"filter.0.value":"10.100.30.68",
}
report_type="html"
tc.check_and_download_workbench(api_keys,filter,"workbench.html",report_type)
'''

api_keys = tc.read_keys("../io_keys.json","ep")
tc.hostIP_html_vuln_report(api_keys,"10.100.30.68,192.168.15.105","workbench.html")
