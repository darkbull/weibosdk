weibosdk
========

主要微博平台开发文档的python封装，调用方式如下：
    api = OAuthApi('appkey', 'appsecret')
    token = api.create_token('http://here.is.callback') # 
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
    
支持新浪，网易微博
