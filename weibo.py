#!/usr/bin/env python
# -*- coding: utf-8 -*-

''' 
    file: weibo.py
    author：darkbull(http://darkbull.net)
    date: 2011-10-22
    desc:
        weibo api的python封装.（基于oauth1.0）
        weibo 微博在线api文档参考：http://open.weibo.com/wiki/API文档
        说明：
            调用接口的参数名称，如果官方文档以":"开始，用"__"代替，例如：:id 用 __id 代替
            
        python版本要求：python2.6+，不支持python3.x
    
    example:
        api = OAuthApi('appkey', 'appsecret')
        token = api.create_token()
        url = token.get_auth_url()
        import webbrowser
        webbrowser.open(url)
        code = raw_input(">>").strip()
        token.set_verifier(code)
        # api.statuses.update.post(token, status = u'测试数据3')
        api.statuses.upload.post(token, status = u'好好学习，天天向上。', pic = '~/test.jpg')
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
    def __init__(self, appkey, appsecret, oauth_token, oauth_token_secret, user_id = 0, original_data = '', callback = 'oob'):
        """
        
        @param callback: 回调方式
        """
        self.appkey = appkey  # 该token对应的应用
        self.appsecret = appsecret  # 该token对应的应用的secret
        # appsecret是可以重置的，重置之后，原有授权过的token将不能再使用。
        
        self.oauth_token = oauth_token
        self.oauth_token_secret = oauth_token_secret
        self.user_id = user_id
        self.original_data = original_data
        self.callback = callback
        
    @property
    def verified(self):
        """Token是否已经授权过
        """
        return True if self.user_id != 0 else False
        
    def __str__(self):
        return self.original_data
        
    def get_auth_url(self, display = 'page'):
        """获取用户授权url
        
        @param display: 参考http://open.weibo.com/wiki/Oauth/authorize
        """
        _AUTHORIZE_URL = 'http://api.t.sina.com.cn/oauth/authorize?oauth_token={token}&display={display}'
        url = _AUTHORIZE_URL.format(token = self.oauth_token, display = display)
        if self.callback.lower().startswith('http'):    # 参考 http://open.weibo.com/wiki/OAuth  "小提示“： 建议始终加上oauth_callback参数
            url += '&oauth_callback=' + urlencode(self.callback)
        return url
        
    _SIGNATURE_BASE_STRING2 = ('POST', 'http://api.t.sina.com.cn/oauth/access_token', 'oauth_consumer_key={app_key}&oauth_nonce={nonce}&oauth_signature_method=HMAC-SHA1&oauth_timestamp={timestamp}&oauth_token={token}&oauth_verifier={verifier}&oauth_version=1.0')
    _ACCESS_TOKEN_URL = 'http://api.t.sina.com.cn/oauth/access_token?oauth_consumer_key={app_key}&oauth_nonce={nonce}&oauth_signature_method=HMAC-SHA1&oauth_timestamp={timestamp}&oauth_token={token}&oauth_verifier={verifier}&oauth_version=1.0&oauth_signature={signature}'
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
            # eg: html: oauth_token=a8caa50e0b6612778b3c849e27e398b2&oauth_token_secret=55729344a581f9acd24ad1551a7cc3cb&user_id=2617375872
        except IOError as ex:
            raise OAuthError(ex)
        if errcode != 200:
            raise OAuthError, (errcode, 'oauth error', reason)
        self.oauth_token, self.oauth_token_secret, user_id = (item.split('=')[1] for item in html.split('&'))
        self.user_id = int(user_id)
            
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
        'User-Agent': 'WeiBo-Python-Client; Created by darkbull(http://darkbull.net)',
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
    
    
_URI_COMMON = 'http://api.t.sina.com.cn/'
def _call(http_method, uri, token, **kwargs):
    if not uri.startswith('http'):
        uri = _URI_COMMON + uri
    if not uri.endswith('.json'):
        uri = uri + '.json'
    http_method = http_method.upper()
        
    params = token.to_header()
    for key, val in kwargs.items():
        if key.startswith('__'):    # 很恶心的参数，如：:id, 这里用 __id代替
            key = ':' + key[2:]
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
        # 错误具体信息查询: http://open.weibo.com/wiki/Error_code
        raise WeiBoError(u'[error:%s occur when request "%s"]:%s' % (json_obj['error_code'],  json_obj['request'], json_obj['error']))
    return DictObject(json_obj)

    
class OAuthApi(object):
    def __init__(self, appkey, appsecret):
        self.appkey = appkey
        self.appsecret = appsecret
        self._attrs = [ ]
        
    _SIGNATURE_BASE_STRING = ('GET', 'http://api.t.sina.com.cn/oauth/request_token', 'oauth_callback={callback}&oauth_consumer_key={app_key}&oauth_nonce={nonce}&oauth_signature_method=HMAC-SHA1&oauth_timestamp={timestamp}&oauth_version=1.0')
    _REQUEST_TOKEN_URL = 'http://api.t.sina.com.cn/oauth/request_token?oauth_callback={callback}&oauth_consumer_key={app_key}&oauth_nonce={nonce}&oauth_signature={signature}&oauth_signature_method=HMAC-SHA1&oauth_timestamp={timestamp}&oauth_version=1.0'
    
    def create_token(self, callback = 'oob'):
        '''创建未授权的request token
        @param callback: 回调地址. oob 表示使用PIN码(桌面应用)
        '''
        n, t, cbk = nonce(), tm(), urlencode(callback)
        http_method, uri, query = OAuthApi._SIGNATURE_BASE_STRING
        args = query.format(callback = cbk, app_key = self.appkey, nonce = n, timestamp = t)
        sig_base_str = '&'.join(urlencode(item) for item in (http_method, uri, args))
        sig = hmac_sha1(self.appsecret + '&', sig_base_str)
        url = OAuthApi._REQUEST_TOKEN_URL.format(callback = cbk, app_key = self.appkey, nonce = n, signature = urlencode(sig), timestamp = t)
        try:
            errcode, reason, html = _request(http_method, url)
            # eg: html: oauth_token=2f74a40e6419251641b4f28fa7aee417&oauth_token_secret=404dcbe420806af2acd4e1583035939d
        except IOError as ex:
            raise OAuthError(ex)
        if errcode != 200:
            raise OAuthError, (errcode, 'oauth error', reason)
        
        token, secret = (item.split('=')[1] for item in html.split('&'))
        token = OAuthToken(self.appkey, self.appsecret, token, secret, original_data = html, callback = callback)
        return token
    
    def __getattr__(self, attr):  
        self._attrs.append(attr)  
        return self  
          
    def __call__(self, token = None, **kwargs):  
        """调用接口，如：api.statuses.public_timeline.get(token) # 以get方式提交请求
        """
        http_method = self._attrs[-1]
        api_uri = '/'.join(self._attrs[:-1])  
        self._attrs = [ ]
        return _call(http_method, api_uri, token, **kwargs)
        
        
# 通过授权的token，可以直接通过 weibo.api.进行调用
api = OAuthApi('', '') 

        
if __name__ == '__main__':
    pass
    