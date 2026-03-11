import json, urllib.request
url='http://127.0.0.1:8000/api/generate'
data=json.dumps({'bits':512}).encode('utf-8')
req=urllib.request.Request(url,data=data,headers={'Content-Type':'application/json'})
res=urllib.request.urlopen(req,timeout=30)
print(res.read().decode())
