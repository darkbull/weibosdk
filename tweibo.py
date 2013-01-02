#!/usr/bin/env python
# -*- coding: utf-8 -*-

''' 
    File: tweibo.py
    Author: DarkBull
    Date: 2011-10-26 
    Modify: 2013-01-02
    
    Desc:
        网易微博api的python封装 (基于oauth1.0)
        api参考文档：http://open.t.163.com/wiki/index.php?title=Document
    
    example:
        api = OAuthApi('appkey', 'appsecret')
        token = api.create_token('http://www.baidu.com')
        url = token.get_auth_url()
        webbrowser.open(url)
        code = raw_input(">>").strip()
        token.set_verifier(code)
        print str(token)
        # ret = api.statuses.user_timeline.get(token)
        # for item in ret:
            # print utf8(item.text)
        api.statuses.update.post(token, status = u'测试数据发布')
        # print api.statuses.upload.post(token, pic = '~/main.jpg')
'''

__version__ = '0.1b'
__author__ = 'darkbull(http://darkbull.net)'


import urllib
import binascii
import time
import random
import json
import httplib
import uuid
import mimetypes
import hmac
import hashlib
from os.path import getsize, isfile, basename
from urlparse import urlparse

hmac_sha1 = lambda key, val: binascii.b2a_base64(hmac.new(str(key), val, hashlib.sha1).digest())[:-1]
nonce = lambda: str(random.randint(1000000, 9999999))
tm = lambda: str(int(time.time()))
utf8 = lambda u: u.encode('utf-8')
urlencode = lambda p: urllib.quote_plus(p, safe = '~')
urldecode = lambda s: urllib.unquote(s)


class OAuthError(IOError):
    pass
    
    
class WeiBoError(Exception):
    pass

    
class DictObject(dict):  
    def __init__(self, d): 
        if isinstance(d, basestring):
            d = json.loads(d)
        dict.__init__(self, d)  
      
    def __getattr__(self, attr):  
        if attr in self:  
            ret = self[attr]  
            if type(ret) is dict:  
                return DictObject(ret)  
            elif type(ret) is list:  
                for idx, item in enumerate(ret):  
                    if type(item) is dict:  
                        ret[idx] = DictObject(item)  
            return ret  
        else:
            raise AttributeError, attr


class OAuthToken(object):
    def __init__(self, appkey, appsecret, oauth_token, oauth_token_secret, original_data = '', callback = 'null'):
        """
        
        @param callback: callback为"null"表示桌面应用。具体参考：http://open.t.163.com/wiki/index.php?title=OAuth%E6%8E%88%E6%9D%83%E8%AF%B4%E6%98%8E
        """
        self.appkey = appkey  # 该token对应的应用
        self.appsecret = appsecret  # 该token对应的应用的secret
        # appsecret是可以重置的，重置之后，原有授权过的token将不能再使用。
        
        self.oauth_token = oauth_token
        self.oauth_token_secret = oauth_token_secret
        self.original_data = original_data  
        self.callback = callback
        
    @property
    def verified(self):
        """Token是否已经授权过
        """
        return bool(self.original_data)
        
    def __str__(self):
        return self.original_data
        
    _AUTHORIZE_URL = 'http://api.t.163.com/oauth/authenticate?oauth_token={token}&client_type={client_type}&oauth_callback={callback}'  # web应用
    _AUTHORIZE_URL2 = 'http://api.t.163.com/oauth/authorize?oauth_token={token}&client_type={client_type}'    # 桌面应用
    def get_auth_url(self, client_type = 'web'):
        '''获取用户授权url
        @param client_type: 客户端类型(不是指应用类型).
        @note: 网易开发平台针对不同的应用类型，授权有点区别(居然用了两个url, fuck...)：
            对于web应用用户授权之后直接跳转到callback，不需要进一步操作(设置oauth_verifier)，原有request token自动变成授权的request token.
            对于非web应用用户授权之后会获取oauth_verifier码，使用该码换取授权过的request token.
        '''
        if self.callback and self.callback.lower().startswith('http'):
            return OAuthToken._AUTHORIZE_URL.format(token = self.oauth_token, callback = urlencode(self.callback), client_type = urlencode(client_type))
        else:
            return OAuthToken._AUTHORIZE_URL2.format(token = self.oauth_token, client_type = urlencode(client_type))
        
    _SIGNATURE_BASE_STRING2 = ('GET', 'http://api.t.163.com/oauth/access_token', 'oauth_consumer_key={app_key}&oauth_nonce={nonce}&oauth_signature_method=HMAC-SHA1&oauth_timestamp={timestamp}&oauth_token={token}&oauth_verifier={verifier}&oauth_version=1.0')
    _ACCESS_TOKEN_URL = 'http://api.t.163.com/oauth/access_token?oauth_consumer_key={app_key}&oauth_nonce={nonce}&oauth_signature_method=HMAC-SHA1&oauth_timestamp={timestamp}&oauth_token={token}&oauth_verifier={verifier}&oauth_version=1.0&oauth_signature={signature}'
    def set_verifier(self, verifier = ''):
        '''通过授权的request token换取access token
        
        @param verifier: 接口实现时似乎不需要。
        '''
        if self.verified:
            raise OAuthError, ('oauth error', 'token is already authorized.')
            
        n, t = nonce(), tm()
        http_method, uri, query = OAuthToken._SIGNATURE_BASE_STRING2
        args = query.format(app_key = self.appkey, nonce = n, timestamp = t, token = self.oauth_token, verifier = verifier)
        sig_base_str = '&'.join(urlencode(item) for item in (http_method, uri, args))
        sig = hmac_sha1('%s&%s' % (self.appsecret, self.oauth_token_secret), sig_base_str)
        url = OAuthToken._ACCESS_TOKEN_URL.format(app_key = self.appkey, nonce = n, signature = urlencode(sig), timestamp = t, token = self.oauth_token, verifier = verifier)
        
        try:
            errcode, reason, html = _request(http_method, url)
            # eg: html: oauth_token=38e16f9c95eef2766b6f018b18d82c7b&oauth_token_secret=7ffdd683624131e75f60f41b5cab6077
        except IOError as ex:
            raise OAuthError(ex)
        if errcode != 200:
            raise OAuthError, (errcode, 'oauth error', reason, html)
            
        self.oauth_token, self.oauth_token_secret = (item.split('=')[1] for item in html.split('&'))
        self.original_data = html
            
    def to_header(self):
        if not self.verified:
            raise OAuthError, ('oauth error', 'unauthorized token.')
        return { 
                'oauth_consumer_key': self.appkey,
                'oauth_token': self.oauth_token,
                'oauth_signature_method': 'HMAC-SHA1',
                'oauth_timestamp': tm(),
                'oauth_nonce': nonce(),
                'oauth_version': '1.0',
            }
        
    
def _request(http_method, url, query = None, timeout = 10, token = None):
    '''向远程服务器发送一个http request
    @param http_method: 请求方法
    @param url: 网址
    @param query: 提交的参数. dict: key: 表单域名称, value: 域值
    @return: 元组(response status, reason, response html)
    '''
    scheme, netloc, path, params, args = urlparse(url)[:5]
    if args:
        path += '?' + args
    conn = httplib.HTTPConnection(netloc, timeout = timeout) if scheme == 'http' else httplib.HTTPSConnection(netloc, timeout = timeout)
    headers = {
        'User-Agent': '163WeiBo-Python-Client; Created by darkbull(http://darkbull.net)',
        'Host': netloc,
    }
    upload_pic = 'statuses/upload' in url
    if token and query:
        # 生成签名
        # 如果有上传图片，只需签名"oauth_"开头的参数. Fuck, 在api文档里没有一点说明，浪费了我n多时间。fuck....
        if upload_pic:
            items = [(key, val) for key, val in query.items() if key.startswith('oauth_')]
        else:
            items = query.items()
        items.sort()
        t = '&'.join(('%s=%s' % (urlencode(key), urlencode(val)) for key, val in items))
        sig_base_str = '%s&%s&%s' % (http_method, urlencode(url), urlencode(t))
        sig = hmac_sha1('%s&%s' % (token.appsecret, token.oauth_token_secret), sig_base_str)
        query['oauth_signature'] = sig
        
        t = [ ]
        auth_header = ['OAuth realm=""']
        for key in query:
            if key.startswith('oauth_'):
                auth_header.append('%s="%s"' % (urlencode(key), urlencode(query[key])))
                t.append(key)
        for key in t:
            del query[key]
        headers['Authorization'] = ', '.join(auth_header)
    
    if upload_pic:    # 需要上传图片
        assert http_method == 'POST'
        assert 'pic' in query
        pic_path = query.pop('pic')
        
        if not isfile(pic_path):
            raise WeiBoError(u'File "{0}" not exist' % pic_path)
        if getsize(pic_path) > 1024 * 1024 * 5: # 新浪微博上传图片大小限制是5M.
            raise WeiBoError('Size of file "{0}" must be less than 5M.' % pic_path)
        
        boundary = '------' + str(uuid.uuid4())
        body = [ ]
        
        if query:
            for field_name, val in query.items():
                body.append('--' + boundary)
                body.append('Content-Disposition: form-data; name="%s"' % field_name)
                body.append('Content-Type: text/plain; charset=US-ASCII')
                body.append('Content-Transfer-Encoding: 8bit')
                body.append('')
                if type(val) is unicode:
                    body.append(utf8(val))
                else:
                    body.append(val)
        
        mimetype = mimetypes.guess_type(pic_path)[0]
        with open(pic_path, 'rb') as f:
            data = f.read()
        filename = basename(pic_path)
        body.append('--' + boundary)
        body.append('Content-Disposition: form-data; name="%s"; filename="%s"' % ('pic', filename))
        if mimetype:
            body.append('Content-Type: ' + mimetype)
        body.append('Content-Transfer-Encoding: binary')
        body.append('')
        body.append(data)
        
        body.append('--' + boundary + '--')
        body.append('')
        body = '\r\n'.join(body)
        
        headers['Content-Type'] = 'multipart/form-data; boundary=' + boundary
        headers['Content-Length'] = str(len(body))
        headers['Connection'] = 'keep-alive'
    else:
        body = urllib.urlencode(query) if query else ''
        if http_method == 'POST':
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
            headers['Content-Length'] = str(len(body))
        else:
            if body:
                if args:
                    path += '&' + body
                else:
                    path += '?' + body
                body = ''
            
    conn.request(http_method, path, body = body, headers = headers)  
    resp = conn.getresponse()
    result = (resp.status, resp.reason, resp.read())
    conn.close()
    return result
    
    
_URI_COMMON = 'http://api.t.163.com/'
def _call(http_method, uri, token, **kwargs):
    if not uri.startswith('http'):
        uri = _URI_COMMON + uri
    if not uri.endswith('.json'):
        uri = uri + '.json'
    http_method = http_method.upper()
        
    params = token.to_header()
    for key, val in kwargs.items():
        if type(key) is unicode:
            key = utf8(key)
        if type(val) is unicode:
            val = utf8(val)
        params[key] = val
    
    try:
        errcode, reason, html = _request(http_method, uri, params, token = token)
    except IOError as ex:
        raise WeiBoError(ex)
    if errcode != 200:
        try:
            json_obj = json.loads(html)
            raise WeiBoError(u'[error:%s occur when request "%s"]:%s' % (json_obj['error_code'],  json_obj['request'], json_obj['error']))
        except WeiBoError:
            raise
        except Exception:
            raise WeiBoError('errcode: %d, reason: %s, html: %s' % (errcode, reason, html))
    
    response = html.decode('utf-8') # utf-8 => unicode
    json_obj = json.loads(response)
    if type(json_obj) is dict and json_obj.get('error_code'):
        raise WeiBoError(u'[error:%s occur when request "%s"]:%s' % (json_obj['error_code'],  json_obj['request'], json_obj['error']))
    return DictObject(json_obj)

    
class OAuthApi(object):
    def __init__(self, appkey, appsecret):
        self.appkey = appkey
        self.appsecret = appsecret
        self._attrs = [ ]
        
    _SIGNATURE_BASE_STRING = ('GET', 'http://api.t.163.com/oauth/request_token', 'oauth_consumer_key={app_key}&oauth_nonce={nonce}&oauth_signature_method=HMAC-SHA1&oauth_timestamp={timestamp}&oauth_version=1.0')
    _REQUEST_TOKEN_URL = 'http://api.t.163.com/oauth/request_token?oauth_consumer_key={app_key}&oauth_nonce={nonce}&oauth_signature={signature}&oauth_signature_method=HMAC-SHA1&oauth_timestamp={timestamp}&oauth_version=1.0'
    def create_token(self, callback = 'null'):
        '''创建未授权的request token
        @param callback: 回调地址. null 表示(桌面应用)
        '''
        n, t, cbk = nonce(), tm(), urlencode(callback)
        http_method, uri, query = OAuthApi._SIGNATURE_BASE_STRING
        args = query.format(app_key = self.appkey, nonce = n, timestamp = t)
        sig_base_str = '&'.join(urlencode(item) for item in (http_method, uri, args))
        sig = hmac_sha1(self.appsecret + '&', sig_base_str)
        url = OAuthApi._REQUEST_TOKEN_URL.format(app_key = self.appkey, nonce = n, signature = urlencode(sig), timestamp = t)
        
        try:
            errcode, reason, html = _request(http_method, url)
            # eg: 200 OK oauth_token=89ed4f0cbff35e3b0a6d17b212b888a2&oauth_token_secret=3368aa297c303e1a3c6751d714d7120f
        except IOError as ex:
            raise OAuthError(ex)
        if errcode != 200:
            raise OAuthError, (errcode, 'oauth error', reason)
        
        token, secret = (item.split('=')[1] for item in html.split('&'))
        token = OAuthToken(self.appkey, self.appsecret, token, secret, original_data = '', callback = callback)
        return token
    
    def __getattr__(self, attr):  
        self._attrs.append(attr)  
        return self  
          
    def __call__(self, token = None, **kwargs):  
        """调用接口，如：api.statuses.public_timeline.get(token) # 以get方式提交请求
        """
        http_method = self._attrs[-1]
        api_uri = '/'.join(self._attrs[:-1])    # statues.home_time.get
        self._attrs = [ ]
        return _call(http_method, api_uri, token, **kwargs)
        
        
# 通过授权的token，可以直接通过 weibo.api.进行调用
api = OAuthApi('', '') 

       
if __name__ == '__main__':
    pass
    