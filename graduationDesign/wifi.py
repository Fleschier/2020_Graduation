import pywifi
import sys
import time
from pywifi import const

# wifi = pywifi.PyWiFi()
# print(wifi.interfaces()[0])
# print()

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

# 扫描wifi并输出
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


def main():
    bies()

if __name__ == '__main__':
    main()