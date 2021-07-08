#!/usr/bin/env python
''' Query Security Hub, export Inspector get_findings
    boto reference: pagination and filtering: https://boto3.amazonaws.com/v1/documentation/api/latest/guide/paginators.html
'''
from botocore.vendored import requests
import sys 
import boto3
import os
import os.path
import getpass 
import configparser
import base64 
import base64
#import rajworks
from datetime import datetime, timedelta,date
import datetime
import logging

import csv
if sys.platform in ['win32', 'darwin']:
    proxy_url = 'http://zsproxy.fanniemae.com:10479'
else:
    proxy_url = 'http://zsproxy.fanniemae.com:9480'

region = 'us-east-1'
outformat = 'json'
today=date.today()
print(today)
filename='/tmp/InspectorFindings-' + str(date.today()) + '.csv'
s3filename=filename.replace("/tmp/",'')

print(filename)
print(s3filename)


region = 'us-east-1'
outformat = 'json'
sslverification = True
awsconfigfile = '/.aws/credentials'



##############################################################################################
# Logging Configuration:
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
# Comment/Uncomment the next line to enable/disable debug logging (to the screen)
logging.disable(logging.CRITICAL)
def lambda_handler(event, context):
 findingSeverity=''
 port=''
 vgw=''
 peeredvpc=''
 client = boto3.client('securityhub')
 s3client=boto3.client('s3')
 s3 = boto3.client('s3')
 paginator1 = client.list_members()
 paginator  = client.get_paginator('get_findings')
 print('test')     
 accountFreq = {}
 with open(filename, mode='w+') as file:
     
    t=os.access('/tmp', os.W_OK) # Check for write access
    print(t)

    writer = csv.writer(file, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)
    #writer.writerow(['AccountId', 'GeneratorId', 'Title','ProductArn','Severity','AppCode','FirstObservedAt','LastObservedAt','CreatedAt','Recommendation','Types','Port','VGW','PEERED_VPC','InstanceId'])print('hello')
    writer.writerow(['AccountId','GeneratorId'])
    
   
 
    file_exist=os.path.exists(filename)
    print(file_exist)
 
    
    for i in  paginator1['Members']:
     accountids=i['AccountId']       
     page_iterator = paginator.paginate(
     Filters={'AwsAccountId': [
            {
                'Value': '713121937993',
                'Comparison': 'EQUALS'
            },
        ],
           'ProductName': [
             { 'Value': 'Inspector',
                  'Comparison':'EQUALS'
                },
        ],         
        
          'SeverityProduct': [
            {
                
                'Gte': 1
            },
            ],
         'Type': [
            {
                'Value': 'Software and Configuration Checks/AWS Security Best Practices/Network Reachability',
                'Comparison': 'PREFIX'
            },
        ],
          
          'CreatedAt': [
            {
                
                'DateRange': {
                    'Value': 200,
                    'Unit': 'DAYS'
                }
                }
                ]
          })
    
    
     for page in page_iterator:
         print(accountids)
         count=0
         for finding in page['Findings']:
          print(finding)
          if finding:
            print("We found something")
          print(accountids)
          findingAccount=finding['AwsAccountId']
          #print (finding.items())
          print(finding['Severity']['Product'])
          scantype = finding['Types']
          str1 = ''.join(scantype)
          print(str1)
          #print(type(scantype))
          if (str1 == 'Software and Configuration Checks/AWS Security Best Practices/Network Reachability - Recognized port reachable from a Peered VPC'):
            print("we have a match")
            vgw=''
            port=finding['ProductFields'][ 'attributes:4/value']
            peeredvpc= finding['ProductFields']['attributes:2/value']
          if (str1 == 'Software and Configuration Checks/AWS Security Best Practices/Network Reachability - Recognized port reachable from a Virtual Private Gateway'):
            peeredvpc=''
            print("we have a match")
            port=finding['ProductFields'][ 'attributes:2/value']
            vgw=finding['ProductFields'][ 'attributes:3/value']
          
          #print(finding['Resources'][0]['Tags']['AppCode'])
         #print(finding['Resources'][0]['Tags']['AssetID'])
          print(finding['LastObservedAt'])
          print(finding['Types'])
          sev = finding['Severity']['Product']
          print(finding['ProductFields'][ 'attributes:4/key'])
          print(finding['ProductFields'][ 'attributes:4/value'])
          if (sev == 3):
              print(findingSeverity)
              findingSeverity='LOW'
          elif (sev == 6):
              findingSeverity='MEDIUM'
          elif ( sev == 9):
              findingSeverity='HIGH'
          print(findingSeverity)
          findingGeneratorId=finding['GeneratorId']
          print(findingGeneratorId)
          findingProductArn=finding['ProductArn']
          findingTitle=finding['Title']
          #findingTags=finding['Tags']
          #findingAppCode=finding['Resources'][0]['Tags']['AppCode']
         #findingAssetId=finding['Resources'][0]['Tags']['AssetID']
          findingLastObservedAt=finding['LastObservedAt']
          findingFirstObservedAt=finding['FirstObservedAt']
          findingCreatedAt=finding['CreatedAt']
          findingrecommendation=finding['Remediation']['Recommendation']
          findingTypes=finding['Types']
          InstanceId=finding['Resources'][0]['Id']
          findingInstanceId=str(InstanceId)
          print(os.getcwd())
          try:
           writer.writerow([findingGeneratorId,'Scott'])
          except Exception as e: 
           print(e)
          #if os.stat('/tmp/writedata3.csv').st_size == 0:
           #print('File is empty')
          #else:
           #print('File is not empty')     
           
          #writer.writerow([findingAccount, findingGeneratorId, findingTitle,findingProductArn,findingSeverity,'Appcode',findingFirstObservedAt,findingLastObservedAt,findingCreatedAt,findingrecommendation,findingTypes,port,vgw,peeredvpc,findingInstanceId])
        #print(findingAccount, ",", findingType)
     
     #if os.stat('/tmp/writedata3.csv').st_size == 0:
      # print('File is empty')
     #else:
       #print('File is not empty')       
    #s3client.upload_file('/tmp/writedata3.csv', 'gentry-inspector', 'scott.csv')
   # print("Writing CSV done")
    #file_exist=os.path.exists('/tmp/writedata3.csv')
    #string = "dfghj"
    #file_name = "hello.txt"
    #lambda_path = "/tmp/" + file_name
    #s3_path = "/100001/20180223/" + file_name

    #with open(lambda_path, 'w+') as file:
     # file.write(string)
      #file.close()

    #s3 = boto3.client('s3')
 s3.upload_file(filename, 'gentry-inspector', s3filename)
 
    
