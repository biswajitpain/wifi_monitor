import urllib.request
import json

def get_public_ip():
    try:
        with urllib.request.urlopen('https://api.ipify.org?format=json') as response:
            data = json.loads(response.read().decode())
            return data['ip']
    except urllib.error.URLError:
        print("Error: Unable to get public IP")
    return None