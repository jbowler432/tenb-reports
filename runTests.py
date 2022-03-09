import tenbCore as tc
import beautifyResults as br
import datetime

'''
# export some compliance data
asset_lst=[]
last_seen="01/07/2021"
int_date=int(datetime.datetime.strptime(last_seen,'%d/%m/%Y').strftime("%s"))
filter_dct={"last_seen":int_date}
num_findings=50
assets=asset_lst
results_file="../results/compliance.json"
api_keys=tc.read_keys("../io_keys.json","sandbox")
chunk_results=tc.check_and_download_compliance_chunks(api_keys,assets,filter_dct,num_findings,results_file)

'''

'''
# export some vuln data
num_assets=50
filters={}
results_file="../results/vulns.json"
api_keys=tc.read_keys("../io_keys.json","sandbox")
chunk_results=tc.check_and_download_vuln_chunks(api_keys,filters,num_assets,results_file)
'''


'''
# export some asset data
api_keys=tc.read_keys("../io_keys.json","sandbox")
filters={}
chunk_size=100
results_file="../results/assets.json"
tc.check_and_download_assets_chunks(api_keys,filters,chunk_size,results_file)
'''

'''
br.compliance_result_summary("../results/compliance.json","../reports/compliance.html")
br.assets_result_summary("../results/assets.json","../reports/assets.html")
br.vuln_result_summary("../results/vulns.json","../reports/vulns2.html")
'''

api_keys=tc.read_keys("../io_keys.json","sandbox")
scans=tc.list_scans(api_keys)
for x in scans['scans']:
	print(x['name'],x['status'],x['id'])

