import hashlib
import time
import os
from requests import request
import uuid

#using SHA-256 instead of md5 because it's 2018 and it's a resource key for VT

BASE_FILES = dict() #filename:sha256
CLEAN_FILES = dict() #sha256:percentage
QUEUED_FILES = dict() #sha256:VTresourceKey
MALICIOUS_FILES = dict() #sha256:percentage
SCAN_URL = "https://www.virustotal.com/vtapi/v2/file/scan"
API_KEY = "bb900653b874bb1f8ae6a6fce55e92676a1810719fa8c5eca04c9af9af1f5b90"
REPORT_URL = "https://www.virustotal.com/vtapi/v2/file/report"
HOME_URL = "http://127.0.0.1:8080/api/add"
THRESHOLD = 1 #percentage threshhold for malicious files
RATE_LIMIT_VT = 15 # changeme to 15 for prod use
RATE_LIMIT_OS = 0.2 # buffer for windows to do its thing
POWER = True # off/on switch
UUID = uuid.uuid4()

def main():
    baseLine()
    while POWER:   
        time.sleep(RATE_LIMIT_VT) 
        scan()
        checkQueue()
        cleanQueues()
        #printQueue() #for debugging

#Cleans processed items from queue - can't delete from dictionary while iterating through it.
def cleanQueues():
    for entry in MALICIOUS_FILES.keys():
        if entry in QUEUED_FILES:
            del QUEUED_FILES[entry]
    for entry in CLEAN_FILES.keys():
        if entry in QUEUED_FILES:
            del QUEUED_FILES[entry]
            
#For debugging - shows status of all dictionaries
def printQueue():
    if len(QUEUED_FILES)==0:
        print("Queue empty")
    else:
        print("Hashes waiting for response from VirusTotal:")
        for item in QUEUED_FILES:   
            print(item)
    if len(CLEAN_FILES)==0:
        print("Clean empty")
    else:
        print("Clean hashes:")
        for item in CLEAN_FILES:
            print(item)
    if len(MALICIOUS_FILES)==0:
        print("Malicious empty")
    else:
        print("Malicious hashes:")
        for item in MALICIOUS_FILES:
            print(item)
            
#whitelists already existing files from scanning            
def baseLine():
    for fname in os.listdir("."):
        if os.path.isfile(fname):
            try:
                sha256 = hashlib.sha256(open(fname,"rb").read()).hexdigest()
                BASE_FILES.update({fname:sha256})
                print("Base file found! Excepting: "+fname+":"+sha256)
            except:
                pass

#Scan for new files and handles whether clean or malicious
def scan():
    for fname in os.listdir("."):
        try:
            if os.path.isfile(fname):
                sha256 = hashlib.sha256(open(fname,"rb").read()).hexdigest()
                if sha256 in MALICIOUS_FILES:
                    deleteFile(fname, sha256)
                    callHome(sha256,fname)
                if sha256 not in CLEAN_FILES.keys() and sha256 not in BASE_FILES.values() and sha256 not in QUEUED_FILES.keys():
                    #Add to queue
                    print("New file found: '"+fname+"'with SHA-256: "+sha256) 
                    uploadFileVT(fname, sha256)
        except:
            pass
        
#deletes files        
def deleteFile(fname, sha256):
        time.sleep(RATE_LIMIT_OS)
        os.remove(fname)
        time.sleep(RATE_LIMIT_OS)
        print("I've found and deleted a malicious file: " +sha256)

#checks virus total for a response for queued files        
def checkQueue():
    for resource in QUEUED_FILES.values():
        response = checkQueueVT(resource)
        if "SCAN FINISHED" in response.text.upper():
            response = response.json()
            total = response["total"]
            positives = response["positives"]
            sha256 = response["sha256"]
            percentage = positives / total * 100            
            if percentage >= THRESHOLD:
                print("Uploaded file determined to be malicious "+sha256)
                MALICIOUS_FILES.update({sha256:percentage})
            else:
                print("Uploaded file determined to be clean "+sha256)
                CLEAN_FILES.update({sha256:percentage})
        else:
            print("No response from VT yet for resource "+resource)
#networking for checkqueue
def checkQueueVT(resource):
    params = {"apikey":API_KEY,"resource":resource}
    response = request("GET", REPORT_URL, params=params)
    return response
            
#uploads a file to VT
def uploadFileVT(fname, sha256):
    params = {"apikey":API_KEY}
    files = {"file":(fname,open(fname,"rb").read())}
    print("Uploading file to VT...")
    response = request("POST", SCAN_URL, files=files, params=params).json()
    resource = response["resource"]
    QUEUED_FILES.update({sha256:resource})
    
#reports to central management server
def callHome(sha256, fname):
    payload = {'agentno':UUID,
           'sha256':sha256,
           'fname':fname,
           'percentage':MALICIOUS_FILES[sha256]}
    response = request("post", HOME_URL, params=payload)
    print("Violation reported to central management server.")

if __name__== "__main__":
    main()
