import os.path, sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))
import tenbIOcore as tc
import utilities as ut
import datetime

# There is no direct update acr api by tag so
# the process is a three step process
# - download the asset info for a tag
# - read the asset info file and produce a list of asset ids
# - update the acrs for the list of asset ids

# file and directory locations
key_file="../../io_keys.json" # location of your key file
results_dir="../results/" # the directory for your results
styles_dir="../styles/" #style sheet location for web pages


# Download asset info for a certain tag.
# You specify the tag_category and tag_value
api_keys=tc.read_keys(key_file,"sandbox")
tag_category="tag.Hosts"
tag_value="group1"
filters={tag_category:tag_value}
chunk_size=300
results_file=results_dir+"assets.json"
payload = {
	"filters":filters,
	"chunk_size": chunk_size
}
tc.check_and_download_assets_chunks(api_keys,payload,results_file)

# Now we have the list of assets, update the acr values
# THe acr score needs to be an integer
asset_lst=ut.extract_assetids(results_file)
acr_score=10
response=tc.update_acr_scores(api_keys,asset_lst,acr_score)
