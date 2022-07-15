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
from datetime import datetime
from datetime import timedelta
warnings.filterwarnings("ignore")

'''
Useful functions
'''

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

def read_json_file(input_file):
	# reads a json file and returns the json object
	with open(input_file,'r') as openfile:
		decoded=json.load(openfile)
	return decoded
