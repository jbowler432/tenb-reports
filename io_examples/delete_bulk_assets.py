import os.path, sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))
import tenbIOcore as tc
import beautifyResults as br
import datetime

# file and directory locations
key_file="../../io_keys.json" # location of your key file
results_dir="../results/" # the directory for your results
styles_dir="../styles/" #style sheet location for web pages

# delete bulk assets by tag
payload = {
	"query": {
	"field": "tag.4BulkDeletion",
	"operator": "eq",
	"value": "192-168-16"
	},
	"hard_delete": True
}
api_keys=tc.read_keys(key_file,"sandbox")
assets_deleted=tc.delete_bulk_assets(api_keys,payload)
print("Deleted "+str(assets_deleted)+" assets")
