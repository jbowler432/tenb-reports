import requests
import json
import time
import os
import csv
import glob
import operator
import socket
import warnings
import sys
import pandas as pd
from datetime import datetime
from datetime import timedelta
warnings.filterwarnings("ignore")

'''
Useful functions
'''

def list_to_string(mylst):
	# for coverting an array of IP addresses into a comma
	# seperated list of ip addresses
	mystring=""
	for x in mylst:
		mystring+=str(x)+", "
	return mystring[:-2]

def get_ip_lst(fname,column_for_ips):
	# reads a csv file containing IP addresses and returns a list
	ip_lst=""
	print("reading "+fname)
	with open(fname) as csv_file:
		csv_reader = csv.reader(csv_file, delimiter=',')
		line_count=0
		for row in csv_reader:
			if len(row)>0:
				#print(row)
				ip_lst+=(row[column_for_ips])+","
				line_count+=1
	print("processed "+str(line_count)+" rows")
	return ip_lst

def unix_time(days):
	# returns the current time as a Unix time
	now=datetime.now()
	date_delta=timedelta(days)
	new_date=now-date_delta
	unixtime=datetime.timestamp(new_date)
	return unixtime

def date_diff(date1,date2):
	# returns the difference between two dates in days
	d1=datetime.fromisoformat(date1.split("T")[0])
	d2=datetime.fromisoformat(date2.split("T")[0])
	return abs((d2-d1).days)

def date_diff_unix(ts1,ts2):
	ttf = (float(ts2)-float(ts1))/(60*60*24)
	return int(ttf)

def read_json_file(input_file):
	# reads a json file and returns the json object
	with open(input_file,'r') as openfile:
		decoded=json.load(openfile)
	return decoded

def dict_subset(dict,keys):
	new_dict={k: dict[k] for k in keys}
	return new_dict

def get_hostname(uuid,input_file):
	decoded=read_json_file(input_file)
	#print(decoded)
	hostname=""
	ipv4=""
	last_seen=""
	for x in decoded:
		if x['id']==uuid:
			hostname=str(x['hostnames'][0])
			ipv4_lst=x['ipv4s']
			last_seen=x['last_seen']
			for x in ipv4_lst:
				ipv4+=x + ' '
	return hostname,ipv4,last_seen

def extract_assetids(input_file):
	with open(input_file,'r') as openfile:
		decoded=json.load(openfile)
	asset_lst=[]
	for x in decoded:
		asset={"id":x["id"]}
		asset_lst.append(asset)
	#print(asset_lst)
	return asset_lst


def found_app(pname,app_lst):
	found=0
	for app in app_lst:
		if app.lower() in pname.lower():
			found=1
	if found==1:
		return True
	else:
		return False

def calculate_fix_sla(df,sla):
	totals=df.groupby('ipv4').apply(lambda df2: sum(df2.ttf>=0)).sum()
	compliant=df.groupby('ipv4').apply(lambda df2: sum(df2.ttf<=sla)).sum()
	not_compliant=df.groupby('ipv4').apply(lambda df2: sum(df2.ttf>sla)).sum()
	return compliant,not_compliant,totals

def calculate_vuln_ages(input_file):
	decoded=read_json_file(input_file)
	count=0
	results=[]
	for x in decoded:
		ffound=x["first_found"]
		lfound=x["last_found"]
		ipv4=x["asset"]["ipv4"]
		uuid=x["asset"]["uuid"]
		pid=x["plugin"]["id"]
		severity=x["severity"]
		vuln_age=date_diff(ffound,lfound)
		lfound_date=lfound.split("T")[0]
		ffound_date=ffound.split("T")[0]
		mydct={'date':pd.to_datetime(lfound_date),'total':vuln_age,severity:vuln_age,'pid':pid,'ipv4':ipv4}
		results.append(mydct)
	return results

def get_vuln_sevs(input_file):
	decoded=read_json_file(input_file)
	count=0
	results=[]
	for x in decoded:
		ipv4=x["asset"]["ipv4"]
		pid=x["plugin"]["id"]
		severity=x["severity"]
		mydct={'severity':severity,'pid':pid,'ipv4':ipv4}
		results.append(mydct)
	return results
