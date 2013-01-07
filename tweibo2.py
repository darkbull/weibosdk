#!/usr/bin/env python
# -*- coding: utf-8 -*-

''' 
    file: tweibo2.py
    author：darkbull(http://darkbull.net)
    date: 2013-01-07
    desc:
        网易微博api的python封装 (基于oauth2.0)
        api参考文档：http://open.t.163.com/wiki/index.php?title=Document
            
        python版本要求：python2.6+，不支持python3.x
    
    example:
        api = OAuth2Api('appkey', 'appsecret', 'callback_url')
        url = api.get_auth_url()
        import webbrowser
        webbrowser.open(url)
        code = raw_input(">>").strip()
        token = api.create_token(code)
        print 'token:', token
        # print api.statuses.upload.post(token, pic = "~/test.jpg")
        print api.statuses.update.post(token, status = u'测试数据2')
'''

__version__ = '0.1a'
__author__ = 'darkbull(http://darkbull.net)'

import urllib
import time
import json
import httplib
import uuid
import mimetypes
from os.path import getsize, isfile, basename
from urlparse import urlparse


utf8 = lambda u: u.encode('utf-8')


class OAuth2Error(IOError):
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
    def __init__(self, appkey, appsecret, access_token, expires_in, uid, original_data = ''):
        self.appkey = appkey
        self.appsecret = appsecret
        self.access_token = access_token
        self.expires_in = expires_in
        self.uid = uid
        self.original_data = original_data
        
    def __str__(self):
        if self.original_data:
            return self.original_data
        return '{access_token: %s, expires_in: %s}' % (self.access_token, self.expires_in)
    
    
def _request(http_method, url, query = None, timeout = 10):
    '''向远程服务器发送一个http request
    
    @param http_method: 请求方法
    @param url: 网址
    @param query: 提交的参数. dict: key: 表单域名称, value: 域值
    @return: 元组(response status, reason, response html)
    '''
    scheme, netloc, path, params, args = urlparse(url)[:5]
    if args:
        path += '?' + args
    conn = httplib.HTTPSConnection(netloc, timeout = timeout) if scheme == 'http' else httplib.HTTPSConnection(netloc, timeout = timeout)
    headers = {
        'User-Agent': '163-WeiBo-Python-Client; Created by darkbull(http://darkbull.net)',
        'Host': netloc,
    }
    
    if 'statuses/upload' in url:    # 需要上传图片
        assert http_method == 'POST'
        assert 'pic' in query
        pic_path = query.pop('pic')
        
        if not isfile(pic_path):
            raise WeiBoError(u'File "{0}" not exist' % pic_path)
        if not (1024 <= getsize(pic_path) <= 1024 * 1024 * 2): # 网易微博上传图片大小限制是1K-2M
            raise WeiBoError('Size of file "{0}" must be less than 2M.' % pic_path)
            
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
        headers['Connection'] = 'close'
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


_URI_COMMON = 'https://api.t.163.com/'
def _call(http_method, uri, token, **kwargs):
    if not uri.startswith('http'):
        uri = _URI_COMMON + uri
    if not uri.lower().endswith('.join'):
        uri += '.json'
    http_method = http_method.upper()
    
    params = { }
    for key, val in kwargs.items():
        if type(key) is unicode:
            key = utf8(key)
        if type(val) is unicode:
            val = utf8(val)
        params[key] = val
        
    if token:
        params['access_token'] = token.access_token
    
    try:
        errcode, reason, html = _request(http_method, uri, params)
    except IOError as ex:
        raise WeiBoError(ex)
    if errcode != 200:
        try:
            json_obj = json.loads(html)
            err = u'[error:%s occur when request "%s"]:%s' % (json_obj['error_code'],  json_obj['request'], json_obj['error'])
            raise WeiBoError(err)
        except WeiBoError:
            raise
        except Exception:
            raise WeiBoError('errcode: %d, reason: %s, html: %s' % (errcode, reason, html))
    
    response = html.decode('utf-8') # utf-8 => unicode
    json_obj = json.loads(response)
    if type(json_obj) is dict and json_obj.get('error_code'):
        # 错误具体信息查询: http://open.t.163.com/wiki/index.php?title=%E9%94%99%E8%AF%AF%E4%BB%A3%E7%A0%81(_error_code_)
        raise WeiBoError(u'[error:%s occur when request "%s"]:%s' % (json_obj['error_code'],  json_obj['request'], json_obj['error']))
    return DictObject(json_obj)


class OAuth2Api(object):
    def __init__(self, appkey, appsecret, callback):
        self.appkey = appkey
        self.appsecret = appsecret
        self.callback = callback    # callback与后台设置的不一致好像也可以正常回调
        self._attrs = [ ]
        
    def get_auth_url(self):
        '''获取用户授权url
        '''
        return 'https://api.t.163.com/oauth2/authorize?client_id=%s&response_type=code&redirect_uri=%s' % (self.appkey, urllib.quote(self.callback))
        
    def create_token(self, code):
        '''获取AccessToken
        '''
        url = 'https://api.t.163.com/oauth2/access_token?client_id=%s&client_secret=%s&redirect_uri=%s&grant_type=authorization_code&code=%s' % (self.appkey, self.appsecret, self.callback, code)
        errcode, reason, html = _request('GET', url)
        # eg: {"uid":"-2129772097311746061","expires_in":"86400","refresh_token":"ce7d36232bad0bda8ef83129e0cb0ca9","access_token":"2d91bbc1a09b825b57694a650cbeaef1"}
        if errcode == 200:
            t = DictObject(json.loads(html))
            return OAuthToken(self.appkey, self.appsecret, t.access_token, int(t.expires_in), t.uid, html)
        else:
            raise OAuth2Error(errcode, reason, html)
    
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


# 通过授权的token，不需要instance OAuthApi，可以直接通过 tweibo2.api.进行调用
api = OAuth2Api('', '', '')  

        
if __name__ == '__main__':
    pass
    
