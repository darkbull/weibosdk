weibosdk
========

主要微博平台开发文档的python封装，调用方式如下：

    api = OAuthApi('appkey', 'appsecret')
    token = api.create_token('http://here.is.callback') # 回调网址
    url = token.get_auth_url()
    webbrowser.open(url)
    code = raw_input(">>").strip()
    token.set_verifier(code)
    # print str(token)
    # 获取时间主线信息
    ret = api.statuses.user_timeline.get(token)
    for item in ret:
        print utf8(item.text)
        
    api.statuses.update.post(token, status = u'调用接口就是这么简单....')  # 调用方法统一为：api_url.http_method
    print api.statuses.upload.post(token, pic = '~/main.jpg')  # 上传图片
    
每个py模块都可单独使用，不依赖其他库。当前实现(2013-01-07):

    weibo2.py: 新浪微博Oauth2.0接口 
    weibo.py: 新浪微博Oauth1.0接口 
    tweibo.py: 网易微博Oauth1.0接口 
    tweibo2.py: 网易微博Oauth2.0接口 
    qweibo.py: 腾讯微博Oauth1.0接口
    qweibo2.py: 腾讯微博Oauth2.0接口

所有模块都可以单独使用，不依赖第三方库。python版本要求2.6+，不支持python3.x.    
