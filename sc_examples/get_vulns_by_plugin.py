import os.path, sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))
import tenbSCcore as sc

# file and directory locations
sc_key_file="../../sc_keys.json"
results_dir="../results/" # the directory for your results
styles_dir="../styles/" #style sheet location for web pages

'''
The sc_keys.json file is a text file with the following format.
It contains a single disctionary object
{"server":"sc server IP","port":"sc server port","user":"secmanager user","password":"user password"}
'''

sc_keys=sc.read_SC_keys(sc_key_file)
sc_server,port,token,cookies=sc.get_token(sc_keys)

pluginID=10863 # this will extract all the certificate information
results_file=results_dir+"cert_info.json"
decoded=sc.get_vulns_by_pluginID(sc_server,port,token,cookies,"10863",results_file)
#print(decoded)


sc.close_session(sc_server,port,token,cookies)
