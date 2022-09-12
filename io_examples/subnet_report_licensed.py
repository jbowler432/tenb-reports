import os.path, sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))
import tenbIOcore as tc
import reportTemplates as rt
import datetime

'''
Generates an asset count by /24 subnet report
'''

# file and directory locations
key_file="../../io_keys.json" # location of your key file
results_dir="../results/" # the directory for your results
styles_dir="../styles/" #style sheet location for web pages
reports_dir="../report_samples/"
#asset_file=results_dir+"unlicensed_assets.json"
asset_file=results_dir+"licensed_assets.json"
#asset_file=results_dir+"assets_with_os.json"
output_file=reports_dir+"subnet_summary_licensed.html"

get_new_data=0

if get_new_data==1:
	# export some asset data
	api_keys=tc.read_keys(key_file,"sandbox")
	filters={"is_licensed": True}
	chunk_size=1000
	payload = {
		"filters":filters,
		"chunk_size": chunk_size
	}
	decoded=tc.check_and_download_assets_chunks(api_keys,payload,asset_file)

rt.assets_subnet_summary(asset_file,output_file,styles_dir)
