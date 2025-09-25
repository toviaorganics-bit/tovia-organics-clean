import requests

try:
    r = requests.get('http://127.0.0.1:5000/api/test-db', timeout=5)
    print('status', r.status_code)
    print(r.text)
except Exception as e:
    print('error', type(e).__name__, str(e))
