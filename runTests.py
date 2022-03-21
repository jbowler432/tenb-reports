import tenbIOcore as tc
import beautifyResults as br
import datetime
'''
# export some asset data
api_keys=tc.read_keys("../io_keys.json","sandbox")
filters={}
chunk_size=300
results_file="../results/assets.json"
tc.check_and_download_assets_chunks(api_keys,filters,chunk_size,results_file)
br.assets_result_summary("../results/assets.json","../reports/assets.html")

# export some compliance data
asset_lst=[]
last_seen="01/01/2021"
int_date=int(datetime.datetime.strptime(last_seen,'%d/%m/%Y').strftime("%s"))
#filter_dct={"last_seen":int_date}
filter_dct={}
num_findings=250
assets=asset_lst
results_file="../results/compliance.json"
api_keys=tc.read_keys("../io_keys.json","sandbox")
chunk_results=tc.check_and_download_compliance_chunks(api_keys,assets,filter_dct,num_findings,results_file)

br.compliance_result_summary("../results/compliance.json","../reports/compliance.html")

# export some vuln data
num_assets=50
filters={}
results_file="../results/vulns.json"
api_keys=tc.read_keys("../io_keys.json","sandbox")
chunk_results=tc.check_and_download_vuln_chunks(api_keys,filters,num_assets,results_file)
br.vuln_result_summary("../results/vulns.json","../reports/vulns.html")



uuid="71a65469-969a-498f-acbe-e960fb7872fc"
name="Tag 'Permissions:10-200' owner permissions"
actions=["CanUse","CanEdit","CanView"]
objects=[{'type':'Tag','uuid':'f5762e64-2a92-4dbe-82d3-3aaac070b85f','name':'Permissions,10-200'}]
subjects=[{'name':'user_restricted@sandbox.io','type':'User','uuid':'3ba739c0-085c-49c8-9613-7a0030ca9716'}]
results=tc.update_permissions(api_keys,uuid,name,actions,objects,subjects)
print(results)
'''

api_keys=tc.read_keys("../io_keys.json","sandbox")

results=tc.list_permissions(api_keys)
for x in results['permissions']:
	print(x,"\n")

results=tc.list_access_groups(api_keys)
for x in results['access_groups']:
	print(x,"\n")
