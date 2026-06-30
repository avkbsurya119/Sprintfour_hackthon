import urllib.request, json
import urllib.error
import mimetypes
import io
import uuid

BASE = 'http://localhost:8000'

def test_upload(filepath):
    with open(filepath, 'rb') as f:
        file_data = f.read()

    boundary = uuid.uuid4().hex
    
    body = bytearray()
    body.extend(f'--{boundary}\r\n'.encode('utf-8'))
    body.extend(f'Content-Disposition: form-data; name=\"file\"; filename=\"{filepath}\"\r\n'.encode('utf-8'))
    body.extend(b'Content-Type: application/octet-stream\r\n\r\n')
    body.extend(file_data)
    body.extend(f'\r\n--{boundary}--\r\n'.encode('utf-8'))

    req = urllib.request.Request(f'{BASE}/api/documents/upload', data=body)
    req.add_header('Content-Type', f'multipart/form-data; boundary={boundary}')
    
    try:
        r = urllib.request.urlopen(req)
        print(f'[{filepath}] SUCCESS: {r.status}')
        print(json.loads(r.read()))
    except urllib.error.HTTPError as e:
        print(f'[{filepath}] ERROR: {e.code}')
        print(e.read().decode('utf-8'))

print('=== TESTING UPLOADS ===')
test_upload('test_with_pii.pdf')
test_upload('test_with_pii.docx')
test_upload('test_corrupt.pdf')
test_upload('test_image_only.pdf')

print('\n=== TEST: Demo document intact ===')
r = urllib.request.urlopen(BASE + '/api/documents/1')
doc = json.loads(r.read())
print('title:', doc['title'])
print('status:', doc['status'])

print('\n=== TEST: List documents ===')
r = urllib.request.urlopen(BASE + '/api/documents')
docs = json.loads(r.read())
for d in docs:
    print('  [' + str(d['id']) + '] ' + d['title'] + ' (is_demo=' + str(d['is_demo']) + ')')
