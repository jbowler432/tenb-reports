import tenbAbstract as ta

host_ip_range="10.100.30.68,192.168.15.105"
ta.ip_vuln_report_html("../io_keys.json","ep",host_ip_range,"workbench.html")
