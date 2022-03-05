import tenbCore as tc
import beautifyCore as bc

api_keys=tc.read_keys("../io_keys.json","sandbox")
results=tc.get_asset_details(api_keys,"3fee0e19-1233-4ba7-98be-f44e4affc015")
print(results["hostname"])
bc.compliance_result_summary("../reports/compliance.json")

import tenbAbstract as ta

#ip_lst=["10.10.1.190"]
#asset_lst=ta.ip_lst_to_asset_lst("../io_keys.json","sandbox",ip_lst)
#asset_lst=["1932a1b3-be7b-45d3-926b-d94599b46ef4"]
asset_lst=["3fee0e19-1233-4ba7-98be-f44e4affc015"]
ta.asset_compliance_export_json("../io_keys.json","sandbox",asset_lst,"../reports/compliance.json")

'''
tag_cat="tag.Hosts"
tag_list=["group1"]
ta.tag_vuln_export_json("../io_keys.json","sandbox",tag_cat,tag_list,"reports/vulns.json")

host_ip_range="192.168.15.101,192.168.15.102,10.200.0.62"
ta.ip_vuln_report_html("../io_keys.json","sandbox",host_ip_range,"reports/workbench.html")

cidr_range="192.168.16.68/32"
ta.cidr_vuln_export_json("../io_keys.json","sandbox",cidr_range,"reports/vulns.json")
'''
