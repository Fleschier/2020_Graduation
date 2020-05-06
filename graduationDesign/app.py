import os
import sys
import tornado.ioloop
import tornado.web
import tornado.websocket
import json
import time
import re

sys.path.append("./")   # 解决import同目录文件错误的问题
import graduationDesign.wifi as wifi
import graduationDesign.DDosCheck as DDosCheck

from tornado.options import define, options

wifis = {}  # 记录搜索到的附近的WiFi。默认为无。
wifis["NO SIGNAL"] = {       # 添加默认项。若搜索到则将此条信息去除
        "description":"Seems no WiFi info right now, \nPlease scan first!",
        "auth":"Unknown",
        "akm":"Unknown",
        "cipher":"Unknown",
        "key":"Unknown",
        "signal":-100, #信号强度，大于-90的信号基本才能使用
        }
profiles = []   # 存储各个wifi的配置信息

def getProfile(wifiname):
    for profile in profiles:
        if(profile.ssid == wifiname):
            return profile
    return "error"

class MainHandler(tornado.web.RequestHandler):
    def get(self):
        self.render("index.html")

class serverHandler(tornado.web.RequestHandler):
    def get(self):
        self.render("server.html")

class wifiHandler(tornado.web.RequestHandler):
    def get(self):
        self.render("wifi.html", wifis=wifis)

# 扫描并显示附近的可用WiFi
class searchWifiHandler(tornado.web.RequestHandler):
    def get(self):
        # profiles = wifi.bies()   # 这有错误，这里的profiles赋值了一个临时变量，函数一结束就会被收回
        tmp = wifi.bies()   # 获取所有的wifi profile配置
        profiles.clear() # 清除缓存
        for tmp_profile in tmp:
            profiles.append(tmp_profile)
        wifis.clear() # 清除缓存
        for item in profiles:
            signal = item.signal
            res = '中等'+ '(' + str(signal) + ')'
            if(signal <= -80): res = '弱'+ '(' + str(signal) + ')'
            elif(signal >= -55): res = '强'+ '(' + str(signal) + ')'
            wifis[item.ssid.encode('raw_unicode_escape').decode('utf-8')]={    # 统一处理防止中文乱码
                "description":"This is an available WiFi~",
                "auth":wifi.auth_algori[item.auth[0]],
                "akm":wifi.akm_types[item.akm[0]],
                "cipher":wifi.cipher_types[item.cipher],
                "key":item.key,
                "signal": res,   # 信号强度
            }
        self.redirect("/wifi")

class connectWifiHandler(tornado.web.RequestHandler):
    def get(self):
        self.redirect("/wifi")
    
    def post(self):
        key = self.get_argument("wifikey")
        # print(key)
        wifiname = self.get_argument('wifiname') ##########从前端获取wifi名称
        # print(wifiname)
        flg = False
        print("ready to connect")
        # for profile in profiles:        # 默认的配置文件貌似信息不全，有问题。无法实现连接，待解决///已解决2020.4.26
        #     print(profile.ssid)
        #     if(wifiname == profile.ssid):
        #         flg = wifi.tryConnect(profile, key)
        #         break
        profile = getProfile(wifiname)
        flg = wifi.tryConnect(profile, key)
        if(flg): self.write("连接成功")
        else: self.write("连接失败")


class compreInspectionHandler(tornado.websocket.WebSocketHandler):

    # 作为静态成员变量，访问时不用加self，正确的访问方式是ClassName.静态变量
    # 静态成员变量用于解决和预防并发执行的错误
    currentWifi = ''    # 存储安全检测时的wifi名称
    currentProfile = ''    # 安全检测时的wifi配置文件
    # 设置响应锁
    basecheck_flg = False
    midmancheck_flg = False
    keycheck_flg = False

    def open(self):     # 连接建立
        print("websocket connected")
        self.write_message(json.dumps({
            'message': '连接已建立...'
        }))

    def on_message(self, message):
        msg = json.loads(message) # 加载信息
        print(msg,'***********************')

        # 获取wifi名称
        if(msg["type"] == "reg"):
            self.write_message(json.dumps({
                'message': '欢迎使用wifi安全检测系统！',
            }))
            compreInspectionHandler.currentWifi = msg['wifiname']
            compreInspectionHandler.currentProfile = getProfile(compreInspectionHandler.currentWifi)
            print("WiFi name: ", compreInspectionHandler.currentWifi)
        
        if(msg["type"] == "basecheck"): 
            # 如果有另一个检测正在进行，挂起
            while(compreInspectionHandler.basecheck_flg | compreInspectionHandler.midmancheck_flg): 
                time.sleep(1)
                continue   
            compreInspectionHandler.basecheck_flg = True
        if(msg["type"] == "midmancheck"): 
            while(compreInspectionHandler.basecheck_flg | compreInspectionHandler.keycheck_flg):
                time.sleep(1)
                continue
            compreInspectionHandler.midmancheck_flg = True
        elif(msg["type"] == "keycheck"): 
            while(compreInspectionHandler.basecheck_flg | compreInspectionHandler.midmancheck_flg):
                time.sleep(1)
                continue
            compreInspectionHandler.keycheck_flg = True
        elif(msg["type"] == "checkall"):
            while(compreInspectionHandler.basecheck_flg | compreInspectionHandler.keycheck_flg | compreInspectionHandler.midmancheck_flg):
                time.sleep(1)
                continue
            compreInspectionHandler.basecheck_flg = True
            compreInspectionHandler.midmancheck_flg = True
            compreInspectionHandlerkeycheck_flg = True

        # 进行常规检测
        if(compreInspectionHandler.basecheck_flg):
            baseSecureCheck(compreInspectionHandler.currentWifi, compreInspectionHandler.currentProfile, self)
            compreInspectionHandler.basecheck_flg = False # 检查完后置flg为False，下同

        # 进行密码强度检测，是否能被短时间暴力破解
        if(compreInspectionHandler.keycheck_flg):
            keyCheck(compreInspectionHandler.currentWifi, compreInspectionHandler.currentProfile, self)
            compreInspectionHandler.keycheck_flg = False

        # 进行wifi真实性检测，防止是中间人之类的伪造wifi
        if(compreInspectionHandler.midmancheck_flg):
            midManCheck(compreInspectionHandler.currentWifi, compreInspectionHandler.currentProfile, self)
            compreInspectionHandler.midmancheck_flg = False

        # 每进行一次检测就关闭本次建立的websocket
        self.close()

    def on_close(self):
        print("websocket closed=====================")

def baseSecureCheck(currentWifi, currentProfile, self):
    self.write_message(json.dumps({
        'message' : '进行基本检测...'
    }))
    self.write_message(json.dumps({
        'message' : '当前检测的WiFi:&nbsp;' + currentWifi
    }))
    currentProfile = getProfile(currentWifi)      # 获取名称对应的wifi的配置文件
    self.write_message(json.dumps({
        'message' : 'WiFi ssid:&nbsp;' + currentProfile.ssid
    }))
    self.write_message(json.dumps({
        'message' : 'WiFi Bssid:&nbsp;' + currentProfile.bssid
    }))
    self.write_message(json.dumps({
        'message' : '认证算法:&nbsp;' + wifi.auth_algori[currentProfile.auth[0]][6:]
    }))
    self.write_message(json.dumps({
        'message' : '密钥管理类型:&nbsp;' + wifi.akm_types[currentProfile.akm[0]][6:]
    }))
    # self.write_message(json.dumps({
    #     'message' : '密码类型:&nbsp;' + wifi.cipher_types[currentProfile.cipher][6:]
    # }))

def keyCheck(currentWifi, currentProfile, self):
    f = open(r'D:\Crs chen\2020_Graduation\graduationDesign\weakpasswd_part.txt', 'r')
    passwds = f.readlines()
    self.write_message(json.dumps({
        'message' : '即将进行字典暴力破解密码测试，可能会耗费一段时间，请耐心等待...'
    }))
    secureFlg = True
    for passwd in passwds:
        # passwd = passwd[:-1]    # 分片，去掉换行符
        self.write_message(json.dumps({'message' : '正在尝试秘钥' + passwd + '...'}))
        flg = wifi.tryConnect(currentProfile, passwd)
        if(flg):
            self.write_message(json.dumps({'message' : '密码已破解！弱密码口令为：' + passwd}))
            secureFlg = False
            break
        else:
            self.write_message(json.dumps({'message' : '连接失败...' + passwd}))
    f.close()
    if(secureFlg):
        self.write_message(json.dumps({'message' : '检测完毕！WiFi安全，可以放心连接~'}))
    else:
        self.write_message(json.dumps({'message' : 'wifi存在安全隐患，密码强度过低！请及时更换密码'}))

def midManCheck(currentWifi, currentProfile, self):
    self.write_message(json.dumps({
        'message' : '进行WiFi真实性检测...'
    }))
    self.write_message(json.dumps({'message' : '功能开发中，敬请期待！'}))
    pass

class listeningHandler(tornado.websocket.WebSocketHandler):
    ddos = DDosCheck.DDosCheck()
    interval = 2    # 设置刷新间隔
    startListening = False   #是否监听

    def open(self):
        pass
    
    def on_message(self, message):
        msg = json.loads(message) # 加载信息
        if(msg['type'] == 'start'): 
            listeningHandler.startListening = True
            print('start')
        if(msg['type'] == 'stop'): #已解决## 目前进度。多线程有问题，无法停止。因为一个on_message方法没有结束，就不能收到另一个信息
            listeningHandler.startListening = False
            print('stop')
        
        if(listeningHandler.startListening):
            # 刷新间隔
            time.sleep(listeningHandler.interval)
            # 每次更新消息之前先清除之前已显示的消息
            self.write_message(json.dumps({
                'type' : "clear",
                #'message' :"none"
            }))

            listeningHandler.ddos.clearInfo() # 更新信息前刷新缓存 
            
            # 更新IP连接信息           
            listeningHandler.ddos.connectCheck()  # 更新
            Info = listeningHandler.ddos.CURRENT_INFO
            blockIP = listeningHandler.ddos.BlOCKING_IP
            # 处理连接信息
            for item in Info:
                # DDosCheck.CURRENT_INFO[item]
                local_ports = list(listeningHandler.ddos.CURRENT_INFO[item]["local_port"])
                local_ports.sort()
                tmp_str = ''
                for i in local_ports:
                    i = str(i)
                    tmp_str += (i + '&&')
                    if(len(tmp_str) >= 10): # 防止过长
                        tmp_str += '&&...'
                        break
                info_message = "{:&<30}{:&^40d}{:&>40}".format(
                    item, 
                    listeningHandler.ddos.CURRENT_INFO[item]["counts"],
                    tmp_str
                    )
                info_message = re.sub('&','&nbsp;',info_message)    # 以浏览器识别的空格字符重新填充
                self.write_message(json.dumps({
                    'type' : "currentInfo",
                    #'message' :item +5*"&nbsp;" + str(listeningHandler.ddos.CURRENT_INFO[item]["counts"]),
                    'message': info_message
                }))
            # 处理被封锁的IP
            for item in blockIP:
                self.write_message(json.dumps({
                    'type' : "blockIP",
                    'message' :item
                }))

            # 更新流量信息
            listeningHandler.ddos.flowCheck()
            total_flow = listeningHandler.ddos.TOTOAL_FLOW
            current_flow = listeningHandler.ddos.CURRENT_FLOW
            # 处理流量信息
            self.write_message(json.dumps({
                'type' : "total_flow",
                'message' :total_flow
            }))
            self.write_message(json.dumps({
                'type' : "current_flow",
                'message' :current_flow
            }))


            # 发送是否继续更新请求
            self.write_message(json.dumps({
                'type' : "continue",
                #'message' :"whether continue?"
            }))
            
        else:
            self.close() # 关闭websocket

    def on_close(self):
        print("websocket stoped")


import uuid
import base64
secret_code = base64.b64encode(uuid.uuid4().bytes)  #使用加密的cookie

settings = {
    'debug': True,
    'template_path': os.path.join(os.path.dirname(__file__), 'templates'),
    'static_path': os.path.join(os.path.dirname(__file__), 'static'),
    'gzip': True,
    'cookie_secret':secret_code,
}

url = [
    (r'/', MainHandler),
    (r'/wifi', wifiHandler),
    (r'/server', serverHandler),
    (r'/search', searchWifiHandler),
    (r'/connect', connectWifiHandler),
    (r'/secure_check', compreInspectionHandler),
    (r'/listen', listeningHandler),
]

define("port", default = 8888, help = "run on the given port", type=int)

def main():
    application = tornado.web.Application(handlers=url, **settings)
    application.listen(options.port)
    print("Development server is running at http://127.0.0.1:%s" % options.port)
    print("Quit the server with Control-C")
    tornado.ioloop.IOLoop.instance().start()

if __name__ == '__main__':
    main()
