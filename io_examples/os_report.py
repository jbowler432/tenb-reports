import os.path, sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))
import tenbIOcore as tc
import beautifyResults as br
import datetime


# file and directory locations
key_file="../../io_keys.json" # location of your key file
results_dir="../results/" # the directory for your results
styles_dir="../styles/" #style sheet location for web pages
#asset_file=results_dir+"licensed_assets.json"
asset_file=results_dir+"assets_with_os.json"
output_file=results_dir+"os_summary.html"

# export some asset data
# make sure the tag is actuially defined in IO
api_keys=tc.read_keys(key_file,"sandbox")
filters={"tag.Operating-Systems": "has-os"}
chunk_size=2000
payload = {
	"filters":filters,
	"chunk_size": chunk_size
}
decoded=tc.check_and_download_assets_chunks(api_keys,payload,asset_file)

br.assets_os_summary(asset_file,output_file,styles_dir)
