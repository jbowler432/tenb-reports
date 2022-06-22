import tenbIOcore as tc
import tenbSCcore as sc
import beautifyResults as br
import datetime

# file and directory locations
key_file="../io_keys.json" # location of your key file
sc_key_file="../sc_keys.json"
results_dir="results/" # the directory for your results
styles_dir="styles/" #style sheet location for web pages

sc_keys=sc.read_SC_keys(sc_key_file)
api_keys=tc.read_keys(key_file,"uni")

'''
payload={}
decoded=tc.list_vuln_filters(api_keys,payload)
for x in decoded["filters"]:
	print(x["name"])

print(" ")
'''

tag_cat="UQ%20Owner"
decoded=tc.list_tag_values(api_keys,tag_cat)
#print(decoded)
for x in decoded["values"]:
	print(x["uuid"])
	print(x["value"])
	print(x["category_name"])

payload = {
	"filter": {"and": [
	{
		"property": "tags",
		"operator": "eq",
		"value": ["a7deb637-89bb-42f4-97b8-68419c72af99"]
	}
	]},
	"limit": 100
}


results=tc.get_asset_count(api_keys,payload)
print(results)
