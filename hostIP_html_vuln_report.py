import tenbCore as tc

api_keys = tc.read_keys("../io_keys.json","ep")
host_ip_range="10.100.30.68,192.168.15.105"
tc.hostIP_html_vuln_report(api_keys,host_ip_range,"workbench.html")
