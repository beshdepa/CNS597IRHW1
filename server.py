from flask import Flask, request
import os

app = Flask(__name__)
files = list()

@app.route("/api/add",methods=["POST"])
def api_add(): #if I were actually writing this I'd probably do some type checking to avoid XSS or whatever
    if not os.path.exists("index.html"):
        generateHomepage()
    tableEntry = '''<tr>
    <th>'''+request.args.get('agentno')+'''</th>
    <th>'''+request.args.get('sha256')+'''</th>
    <th>'''+request.args.get('fname')+'''</th>
    <th>'''+request.args.get('percentage')+'''%</th>
</tr>
'''
    with open ("index.html", "a") as index:
        index.write(tableEntry)
    return("Thank you for your submission of: "+tableEntry)
    
@app.route("/index")
@app.route("/")
def root():
    if not os.path.exists("index.html"):
        return generateHomepage()
    with open("index.html", 'r') as index:
        toClient = index.read()
        return toClient

def generateHomepage():
    basepage = '''<title>Cyber Security Automation Server</title>
<h1 align="center">Reported files!</h1>
<table style="width:100%">
    <tr>
        <th>Agent-Number</th>
        <th>SHA-256</th> 
        <th>File-Name</th>
        <th>Percentage</th>
    </tr>
    '''
    with open("index.html", 'w+') as index:
            print("No index.html detected. Generating.")
            index.write(basepage)
    return basepage
    

if __name__ == "__main__":
    app.run(host="0.0.0.0",port=8080)
