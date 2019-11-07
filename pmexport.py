#!/usr/bin/python3
import base64, json, hashlib, os, re, sys, tempfile
import bcrypt, gnupg, requests

mailbox_pw = b'password'
key_salt = b'Y2QzNmIzNzA3NThhMjU5Yj=='
gpg_key = open('key').read()
curl = open('curl').read().replace('"%"', '%')
cookie = re.search(r'Cookie: ([^"]+)', curl).group(1)

cache_dir = '.cache'
output_dir = 'output'

base64_alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
bcrypt_alphabet = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
b64_to_bc = bytes.maketrans(base64_alphabet, bcrypt_alphabet)
gpg_pw = bcrypt.hashpw(mailbox_pw, b'$2y$10$' + key_salt.translate(b64_to_bc))[29:].decode()

api = "https://mail.protonmail.com/api"
# https://github.com/ProtonMail/WebClient/blob/public/src/app/constants.js
mailbox_id = {0:'Inbox', 1:'Drafts', 2:'Sent', 3:'Trash', 4:'Spam', 5:'All Mail'}
ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:68.0) Gecko/20100101 Firefox/68.0'

uid = re.search(r'AUTH-([0-9a-f]+)=', cookie).group(1)
headers = {"Cookie": cookie, "User-Agent": ua, "x-pm-uid": uid,
"x-pm-appversion": "Web_3.16.6", "x-pm-apiversion": "3"}

s = requests.Session()
s.headers.update(headers)

def mkdir(dir):
    if not os.path.isdir(dir): os.mkdir(dir)

def hash(data, len=12):
    if isinstance(data, str): data = str.encode(data)
    return hashlib.sha1(data).hexdigest()[:len]

def decrypt(data):
    if isinstance(data, str): data = str.encode(data)
    for i in range(5):
        dec = gpg.decrypt(data, passphrase=gpg_pw)
        if dec.ok: return dec.data
    raise RuntimeError(dec.status)

def get_blob(path, cache=True):
    cached_path = cache_dir + os.sep + hash(path, 40)
    if cache and os.path.exists(cached_path):
        return open(cached_path, 'rb').read()
    print('API:', path)
    r = s.get(api + path, timeout=120)
    if r.status_code != 200:
        raise RuntimeError("HTTP status code %d"%r.status_code)
    with open(cached_path, 'wb') as f: f.write(r.content)
    return r.content

def get(path, cache=True):
    resp = json.loads(get_blob(path))
    if resp["Code"] != 1000:
        raise RuntimeError("API status code %d"%resp["Code"])
    return resp

def get_count():
    r = get("/messages/count", False)
    return {i["LabelID"]: i["Total"] for i in r["Counts"]}

def get_label(id, total):
    pages = range(total//100 + 1)
    for page in pages:
        r = get("/messages?Label=%s&Limit=100&Page=%d"%(id, 2 * page), False) # XXX: 2*page
        assert r["Total"] == total
        for msg in r["Messages"]:
            get_msg(msg["ID"])

def get_msg(id):
    r = get("/messages/%s"%id)
    msg = r["Message"]

    mbox_id = msg["Location"]
    folder = mailbox_id.get(mbox_id, str(mbox_id))

    hdr = msg["Header"]
    body = msg["Body"]
    time = msg["Time"]
    if msg["IsEncrypted"]: body = decrypt(body)

    eml_name = '%d.%s'%(time, hash(id))
    write(folder, eml_name + '.eml', hdr.encode() + b"\r\n" + body)

    for att in msg.get("Attachments", []):
        att_id = att["ID"]
        att_name = att["Name"]
        hdr = base64.b64decode(att["KeyPackets"])
        pld = get_att(att_id)
        decrypted = decrypt(hdr + pld)
        write(folder, '%s.%s.%s'%(eml_name, hash(att_id), att_name), decrypted)

def get_att(id):
    return get_blob("/attachments/%s"%id)

def write(folder, fname, content):
    dir = output_dir + os.sep + folder
    out = dir + os.sep + fname
    mkdir(dir)
    if os.path.exists(out):
        print(out, "already exists, skipping...")
    with open(out, 'wb') as f: f.write(content)

mkdir(cache_dir)
mkdir(output_dir)
gpg_tempdir = tempfile.mkdtemp()
gpg = gnupg.GPG(gnupghome=gpg_tempdir)
import_result = gpg.import_keys(gpg_key)
assert import_result.count == 1

count = get_count()['5']
print('Fetching %d messages...'%count)
get_label('5', count)
