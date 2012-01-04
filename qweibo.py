#!/usr/bin/env python
# -*- coding: utf-8 -*-

''' 
    file: qweibo.py
    author：darkbull(http://darkbull.net)
    date: 2011-10-22
    modify: 2013-01-03 (说明：使用动态方法调用api)
    modify: 2013-01-04 (说明：bug fix: del是python关键字，使用delete代替)
    desc:
        QQ微博api的python封装.(基于OAuth1.0)
        QQ微博Oauth1.0授权过程参考：http://wiki.open.t.qq.com/index.php/OAuth%E6%8E%88%E6%9D%83%E8%AF%B4%E6%98%8E
        QQ微博在线api文档参考：http://open.t.qq.com/resource.php?i=1,0
        说明：
            . 所有的api封装方法名均与官方api文档描述保持一致(除del外，del是python关键字，这里改成delete)
            . 所有api接口调用的第一个参数必须是access token，不管该api在官方文档里是否要求鉴权
            . 参数必须以命名参数的形式传递, 如：OAuthApi('appkey', 'appsecret').t.add(token, content = u'天朝SB一大堆，你抄我嘞我抄你。')。如果要传递字符串参数，请使用unicode。
        
        python版本要求：python2.6+，不支持python3.x

    note: 接口调用是非线程安全，同一个OAuthApi对象，在多线程中调用是不安全的。
    
    example:
        api = OAuthApi('app_key', 'app_secret')
        token = api.create_token('http://callback.url') # 获取未授权的token
        url = token.get_auth_url()
        import webbrowser
        webbrowser.open(url)
        code = raw_input(">>").strip()
        token.set_verifier(code)    # token授权，并换取access token.

        #print api.t.add.post(token, content = u'数据测试')  # api 调用
        print api.t.add_pic.post(token, content = u'选择python，选择简洁', pic = '/Users/kim/Desktop/test.JPG')
        print api.t.delete.post(token, id = 140887054982728)    # 删除微博, del 是py关键字，用delete代替
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
        if isinstance(d, basestring):   # json-string
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
    def __init__(self, appkey, appsecret, oauth_token, oauth_token_secret, name = '', original_data = '', callback = 'null'):
        """
        
        @param oauth_token: 授权过的token
        @param oatuh_token_secret: 授权过的token_secret
        @param name: 授权用户名
        @param original_data: 授权token的原始数据
        @param callback: 回调方式. "null"表示为桌面应用
        """
        self.appkey = appkey  # 该token对应的应用
        self.appsecret = appsecret  # 该token对应的应用的secret
        # appsecret是可以重置的，重置之后，原有授权过的token将不能再使用。
        
        self.oauth_token = oauth_token
        self.oauth_token_secret = oauth_token_secret
        self.name = name    # 用户名称
        self.original_data = original_data
        self.callback = callback
        
    @property
    def verified(self):
        """Token是否已经授权过
        """
        return bool(self.original_data)
        
    def __str__(self):
        return self.original_data
        
    def get_auth_url(self):
        """获取用户授权url
        """
        _AUTHORIZE_URL = 'https://open.t.qq.com/cgi-bin/authorize?oauth_token=%s'
        url = _AUTHORIZE_URL % self.oauth_token
        return url
        
    _SIGNATURE_BASE_STRING2 = ('GET', 'https://open.t.qq.com/cgi-bin/access_token', 'oauth_consumer_key={app_key}&oauth_nonce={nonce}&oauth_signature_method=HMAC-SHA1&oauth_timestamp={timestamp}&oauth_token={token}&oauth_verifier={verifier}&oauth_version=1.0')
    _ACCESS_TOKEN_URL = 'https://open.t.qq.com/cgi-bin/access_token?oauth_consumer_key={app_key}&oauth_nonce={nonce}&oauth_signature_method=HMAC-SHA1&oauth_timestamp={timestamp}&oauth_token={token}&oauth_verifier={verifier}&oauth_version=1.0&oauth_signature={signature}'
    def set_verifier(self, verifier):
        '''通过授权的request token换取access token
        '''
        if self.verified:
            raise OAuthError, ('oauth error', 'token is already authorized.')
            
        n, t = nonce(), tm()
        http_method, uri, query = OAuthToken._SIGNATURE_BASE_STRING2
        args = query.format(app_key = self.appkey, nonce = n, timestamp = t, token = self.oauth_token, verifier = verifier)
        sig_base_str = '&'.join(urlencode(item) for item in (http_method, uri, args))
        sig = hmac_sha1('%s&%s' % (self.appsecret, self.oauth_token_secret), sig_base_str)  # 新浪的weibo签名验证只检查前x位
        url = OAuthToken._ACCESS_TOKEN_URL.format(app_key = self.appkey, nonce = n, signature = urlencode(sig), timestamp = t, token = self.oauth_token, verifier = verifier)
        
        try:
            errcode, reason, html = _request(http_method, url)
            # eg: html: oauth_token=6c27e9ce637c4ef8a6f280fe7e548b47&oauth_token_secret=132adfac68b1cba94dab0a4e6da74c7e&name=shaoxinglao9
        except IOError as ex:
            raise OAuthError(ex)
        if errcode != 200:
            raise OAuthError, (errcode, 'oauth error', reason)
        self.original_data = html
        self.oauth_token, self.oauth_token_secret, self.name = (item.split('=')[1] for item in html.split('&'))
            
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
                'format': 'json',   # NOTE: 通过json与服务器交互。在调用api时不允许再设置format参数
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
        'User-Agent': 'QQWeiBo-Python-Client;Created by darkbull(http://darkbull.net)',
        'Host': netloc,
    }
    upload_pic = 't/add_pic' in url
    if token and query:
        # 生成签名
        if upload_pic:
            items = [(key, val) for key, val in query.items() if key != 'pic']
        else:
            items = query.items()
        items.sort()
        t = '&'.join(('%s=%s' % (urlencode(key), urlencode(val)) for key, val in items))
        sig_base_str = '%s&%s&%s' % (http_method, urlencode(url), urlencode(t))
        sig = hmac_sha1('%s&%s' % (token.appsecret, token.oauth_token_secret), sig_base_str)
        query['oauth_signature'] = sig

    if upload_pic:    # 需要上传图片
        assert http_method == 'POST'
        assert 'pic' in query
        pic_path = query.pop('pic')
        
        if not isfile(pic_path):
            raise WeiBoError(u'File "{0}" not exist' % pic_path)
        if getsize(pic_path) > 1024 * 1024 * 4: # qq微博上传图片大小限制是4M.
            raise WeiBoError('Size of file "{0}" must be less than 4M.' % pic_path)
        
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
        
        body.append('--' + boundary)
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
    
    
_URI_COMMON = 'http://open.t.qq.com/api/'
def _call(http_method, uri, token, **kwargs):
    if not uri.startswith('http'):
        uri = _URI_COMMON + uri
    http_method = http_method.upper()
    params = token.to_header()
    for key, val in kwargs.items():
        if type(key) is unicode:
            key = utf8(key)
        if type(val) is unicode:
            val = utf8(val)
        params[str(key)] = str(val)
    
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
        # 错误码说明，参考：http://open.t.qq.com/resource.php?i=1,1#21_90
        raise WeiBoError(u'[error:%s occur when request "%s"]:%s' % (json_obj['error_code'],  json_obj['request'], json_obj['error']))
    return DictObject(json_obj)

    
class OAuthApi(object):
    def __init__(self, appkey, appsecret):
        self.appkey = appkey
        self.appsecret = appsecret
        self._attrs = [ ]
        
    _SIGNATURE_BASE_STRING = ('GET', 'https://open.t.qq.com/cgi-bin/request_token', 'oauth_callback={callback}&oauth_consumer_key={app_key}&oauth_nonce={nonce}&oauth_signature_method=HMAC-SHA1&oauth_timestamp={timestamp}&oauth_version=1.0')
    _REQUEST_TOKEN_URL = 'https://open.t.qq.com/cgi-bin/request_token?oauth_callback={callback}&oauth_consumer_key={app_key}&oauth_nonce={nonce}&oauth_signature={signature}&oauth_signature_method=HMAC-SHA1&oauth_timestamp={timestamp}&oauth_version=1.0'
    def create_token(self, callback = 'null'):
        '''创建未授权的request token
        
        @param callback: 回调地址. 
        '''
        n, t, cbk = nonce(), tm(), urlencode(callback)
        http_method, uri, query = OAuthApi._SIGNATURE_BASE_STRING
        args = query.format(callback = cbk, app_key = self.appkey, nonce = n, timestamp = t)
        sig_base_str = '&'.join(urlencode(item) for item in (http_method, uri, args))
        sig = hmac_sha1(self.appsecret + '&', sig_base_str)
        url = OAuthApi._REQUEST_TOKEN_URL.format(callback = cbk, app_key = self.appkey, nonce = n, signature = urlencode(sig), timestamp = t)
        try:
            errcode, reason, html = _request(http_method, url)
            # eg: html: oauth_token=7e5e7d6528f24aab9cdeb93b2ec14797&oauth_token_secret=d2c25863e3e1560692dad47d4d1b1826&oauth_callback_confirmed=true
        except IOError as ex:
            raise OAuthError(ex)
        if errcode != 200:
            raise OAuthError, (errcode, 'oauth error', reason)
        
        token, secret, _ = (item.split('=')[1] for item in html.split('&'))
        token = OAuthToken(self.appkey, self.appsecret, token, secret, original_data = '', callback = callback)
        return token
    
    def __getattr__(self, attr):  
        self._attrs.append(attr)  
        return self  
          
    def __call__(self, token = None, **kwargs):  
        """调用接口，如：api.statuses.public_timeline.get(token) # 以get方式提交请求
        """
        http_method = self._attrs[-1]
        # del是python关键字，使用delete代替
        attrs = ['del' if part == 'delete' else part for part in self._attrs[:-1]]
        api_uri = '/'.join(attrs)  
        self._attrs = [ ]
        return _call(http_method, api_uri, token, **kwargs)
        
        
# 通过授权的token，不需要instance OAuthApi，可以直接通过 qweibo.api.进行调用
api = OAuthApi('', '') 

        
if __name__ == '__main__':
    pass
    
    
    
    