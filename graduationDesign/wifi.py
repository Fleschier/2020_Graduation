import pywifi
import sys
import time
from pywifi import const
import os

from scapy.all import *
from scapy.sendrecv import sendp
from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap, Dot11Beacon, Dot11Elt, Dot11ProbeResp
import logging

# 所有状态 
ifaces_status = [
"IFACE_DISCONNECTED",
"IFACE_SCANNING",
"IFACE_INACTIVE",
"IFACE_CONNECTING", 
"IFACE_CONNECTED"]

# 认证算法
auth_algori = [
    "const.AUTH_OPEN",
    "const.AUTH_SHARED"
]

# 密钥管理类型
akm_types = [
    "const.AKM_TYPE_NONE",
    "const.AKM_TYPE_WPA",
    "const.AKM_TYPE_WPAPSK",
    "const.AKM_TYPE_WPA2",
    "const.AKM_TYPE_WPA2PSK"
]

# 密码类型
cipher_types = [
    "const.CIPHER_TYPE_NONE",
    "const.CIPHER_TYPE_WEP",
    "const.CIPHER_TYPE_TKIP",
    "const.CIPHER_TYPE_CCMP"
]

# 扫描wifi获取profiles列表
def bies():
    wifi=pywifi.PyWiFi()#创建一个无限对象
    ifaces=wifi.interfaces()[0]#取一个无限网卡，一般只有一个，故取0
    print('interface name: ' + ifaces.name())
    ifaces.scan()#扫描
    # Because the scan time for each Wi-Fi interface is variant. 
    # It is safer to call scan_results() 2 ~ 8 seconds later after calling scan().
    time.sleep(2)

    bessis=ifaces.scan_results()        # A Profile list will be returned. 返回的是一个Profile列表
    # for one_profile in bessis:
    #     #print('ssid: ', one_profile.ssid) #wifi名称
    #     print('ssid:', one_profile.ssid.encode('raw_unicode_escape').decode('utf-8')) # 解决中文wifi名乱码问题
    #     for i in one_profile.auth:  # 返回的是一个int列表
    #         print('auth: ', auth_algori[i]) # 认证算法
    #     for j in one_profile.akm:
    #         print('akm: ', akm_types[j]) # 密钥管理类型 一般为const.AKM_TYPE_WPA2PSK，如果未加密则为const.AKM_TYPE_NONE
    #     print('cipher: ', cipher_types[one_profile.cipher]) # 密码类型
    #     print('key: ', one_profile.key) # 密码
    #     print("-------------------")
    # print(ifaces_status[ifaces.status()])   # iface.status()返回一个index，其顺序与上面的list对应
    return bessis

# A Profile is the settings of the AP we want to connect to. The fields of an profile:
# ssid - The ssid of the AP.
# auth - The authentication algorithm of the AP.
# akm - The key management type of the AP.
# cipher - The cipher type of the AP.
# key (optinoal) - The key of the AP. This should be set if the cipher is not CIPHER_TYPE_NONE.

# 尝试连接目标网络
def tryConnect(profl, passwd):
    wifi = pywifi.PyWiFi()
    ifaces = wifi.interfaces()[0]
    print(ifaces.name()) # 网卡名称

    if ifaces.status() == const.IFACE_CONNECTED:
        ifaces.disconnect()  # 断开现有连接

    profile = profl # 获取profile，即配置文件信息
    profile.cipher = const.CIPHER_TYPE_CCMP #设置秘钥类型，这个不能少。通过接口获取的信息不全导致如果不设置cipher类型会连接失败
    profile.key = passwd    # 设置profile秘钥，即wifi密码

    ifaces.remove_all_network_profiles()    #删除其他配置文件
    tmpProfile = ifaces.add_network_profile(profile)    # 添加当前配置文件
    ifaces.connect(tmpProfile)  # 按照配置文件进行连接
    time.sleep(2)   # 等待几秒连接

    print("iface_status: ", ifaces.status())
    if(ifaces.status() == const.IFACE_CONNECTED): # 连接成功
        return True
    else:
        return False

class FakeWifiCheck():
    blacklist = set()
    def __init__(self):
        self.info_list = [] # 记录所有的信息
        self.blacklist = set()  # 记录所有的黑名单SSID
        self.pp = {}            # 记录所有的BSSID及其对应的所有SSID
        # self.channel = ''

    def sniff_channel_hop(self):
        # for i in range(1, 14):
            # os.system("iwconfig " + self.iface + " channel " + str(i))
        # sniff(count=4, prn=self.air_scan)   # prn：为每个数据包定义一个回调函数
        sniff(count=10, prn=self.air_scan, timeout=15) 


    def air_scan(self, pkt):
        """
        Scan all network with channel hopping
        Collected all ssid and mac address information
        :param pkt:  result of sniff function
        """
        print("air_scan is running!")
        pkt.show()
        if pkt.haslayer(Dot11ProbeResp):    # 判断是否是 802.11 Probe Response 类型的
            ssid, bssid = pkt.info, pkt.addr2
            info = "{}=*={}".format(bssid, ssid)

            print("info: ", info)

            if info not in self.info_list:
                self.info_list.append(info)


    def pp_analysis(self):
        """
        Analysis air_scan result for pineAP Suite detection
        """
        for i in self.info_list:

            bssid, ssid= i.split("=*=")
            if (bssid not in self.pp.keys()): # 如果bssid未记录
                self.pp[bssid] = {ssid,}
                # self.pp[bssid].add(ssid)
            elif (bssid in pp.keys() and ssid not in self.pp[bssid]): # 如果已经存在该bssid记录
                self.pp[bssid].add(ssid)

        """
        Detects KARMA Attack.
        """
        for v in self.pp.keys():
            if (len(self.pp[v]) >= 2):  # 如果BSSID是伪造了多个IP
                print ("KARMA Attack activity detected.", 'magenta')
                print (" MAC Address : ", v)
                print (" FakeAP count: ", len(self.pp[v]))

            # 将该BSSID所有伪造的SSID列入黑名单
            for item in pp[v]:      
                self.blacklist.add(item)
        # time.sleep(3)


    # def find_channel(self, clist, v):
    #     for i in range(0, len(clist)):
    #         if clist[i].haslayer(Dot11ProbeResp) and clist[i].addr2 == v:
    #             self.channel = ord(clist[i][Dot11Elt:3].info)



def main():
    # bies()
    fakecheck = FakeWifiCheck()
    fakecheck.sniff_channel_hop()
    fakecheck.pp_analysis()

if __name__ == '__main__':
    main()