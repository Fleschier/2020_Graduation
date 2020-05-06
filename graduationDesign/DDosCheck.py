from subprocess import Popen, PIPE
import re
import time

import dpkt
import socket
import optparse
"""

显示协议统计信息和当前 TCP/IP 网络连接。
NETSTAT [-a] [-b] [-e] [-f] [-n] [-o] [-p proto] [-r] [-s] [-x] [-t] [interval]
  -a            显示所有连接和侦听端口。
  -b            显示在创建每个连接或侦听端口时涉及的
                可执行程序。在某些情况下，已知可执行程序承载
                多个独立的组件，这些情况下，
                显示创建连接或侦听端口时
                涉及的组件序列。在此情况下，可执行程序的
                名称位于底部 [] 中，它调用的组件位于顶部，
                直至达到 TCP/IP。注意，此选项
                可能很耗时，并且在你没有足够
                权限时可能失败。
  -e            显示以太网统计信息。此选项可以与 -s 选项
                结合使用。
  -f            显示外部地址的完全限定
                域名(FQDN)。
  -n            以数字形式显示地址和端口号。
  -o            显示拥有的与每个连接关联的进程 ID。
  -p proto      显示 proto 指定的协议的连接；proto
                可以是下列任何一个: TCP、UDP、TCPv6 或 UDPv6。如果与 -s
                选项一起用来显示每个协议的统计信息，proto 可以是下列任何一个:
                IP、IPv6、ICMP、ICMPv6、TCP、TCPv6、UDP 或 UDPv6。
  -q            显示所有连接、侦听端口和绑定的
                非侦听 TCP 端口。绑定的非侦听端口
                 不一定与活动连接相关联。
  -r            显示路由表。
  -s            显示每个协议的统计信息。默认情况下，
                显示 IP、IPv6、ICMP、ICMPv6、TCP、TCPv6、UDP 和 UDPv6 的统计信息; 
                -p 选项可用于指定默认的子网。
  -t            显示当前连接卸载状态。
  -x            显示 NetworkDirect 连接、侦听器和共享
                终结点。
  -y            显示所有连接的 TCP 连接模板。
                无法与其他选项结合使用。
  interval      重新显示选定的统计信息，各个显示间暂停的
                间隔秒数。按 CTRL+C 停止重新显示
                统计信息。如果省略，则 netstat 将打印当前的
                配置信息一次。
 
netstat -an中state含义 
LISTEN：侦听来自远方的TCP端口的连接请求 
SYN-SENT：再发送连接请求后等待匹配的连接请求 
SYN-RECEIVED：再收到和发送一个连接请求后等待对方对连接请求的确认 
ESTABLISHED：代表一个打开的连接 
FIN-WAIT-1：等待远程TCP连接中断请求，或先前的连接中断请求的确认 
FIN-WAIT-2：从远程TCP等待连接中断请求 
CLOSE-WAIT：等待从本地用户发来的连接中断请求 
CLOSING：等待远程TCP对连接中断的确认 
LAST-ACK：等待原来的发向远程TCP的连接中断请求的确认 
TIME-WAIT：等待足够的时间以确保远程TCP接收到连接中断请求的确认 
CLOSED：没有任何连接状态
"""
"""
被DDoS攻击时的现象：

· 被攻击主机上有大量等待的TCP连接。

· 网络中充斥着大量的无用的数据包，源地址为假。

· 制造高流量无用数据，造成网络拥塞，使受害主机无法正常和外界通讯。

· 利用受害主机提供的服务或传输协议上的缺陷，反复高速的发出特定的服务请求，使受害主机无法及时处理所有正常请求。

· 严重时会造成系统死机。"""

import chardet

class DDosCheck():

    def __init__(self):
        self.CONCURRENCY_ALLOWED = 30   # 默认允许的最大连接数
        self.OUTDATE_TIME = 86400
        self.CURRENT_INFO = {}   # 存储当前活动连接状态
        self.BlOCKING_IP = set() # 存储黑名单
        self.CURRENT_FLOW = {"Ipv4":0,"Ipv6":0}  # 当前流量速度，分段/秒
        self.TOTOAL_FLOW = 0     # 从开始监听时起累计接收的分段数

    def setMaxConcurrency(self, max):
        self.CONCURRENCY_ALLOWED = max

    def clearInfo(self):
        self.CURRENT_INFO.clear()
        self.BlOCKING_IP.clear()

    # 检查建立连接的端口和IP
    def connectCheck(self):
        # 使用windows的 netstat命令来查询所有端口的状态
        pipe = Popen("netstat -vn", shell=True, bufsize=1024, stdout=PIPE).stdout
        info = pipe.read()  # 获取bytes串

        #print(type(info))
        #print(chardet.detect(info)) # 获取串的编码为 GB2312
        strArr = bytes.decode(info, "GB2312").split('\n')
        #print(strArr[3])    # strArr[3]为表头（ 协议  本地地址   外部地址    状态），之后才是数据，前面的是无效数据
        # print(strArr[4]) # 每条string的内容： TCP  127.0.0.1:7890      127.0.0.1:52149   ESTABLISHED
        #for item in strArr:
        for i in range(4, len(strArr)):
            item = strArr[i]
            if(len(item) <= 10): continue
            #print(item)
            pattern = re.compile("\s+")     # 匹配多个空白字符
            item = pattern.split(item)
            # print(item) # 格式：['', 'TCP', '127.0.0.1:7890', '127.0.0.1:52751', 'ESTABLISHED', '']
            outsideIP = item[3].split(":")[0]   # 去除端口号，仅保留IP
            localPort = item[2].split(":")[1]   # 保留端口号
            if(localPort == ''): continue   # 去除错误

            if(outsideIP == "127.0.0.1 "): continue # 去除本机IP

            if(outsideIP not in self.CURRENT_INFO):  # 以外部ip地址为字典键
                self.CURRENT_INFO[outsideIP] = {
                    "protocol": item[1],
                    "local_port":{int(localPort),},  # 用集合来存，去重方便
                    "status":{item[4],},
                    "counts":1,
                }
            else:
                self.CURRENT_INFO[outsideIP]["local_port"].add(int(localPort))
                self.CURRENT_INFO[outsideIP]["status"].add(item[4])
                self.CURRENT_INFO[outsideIP]["counts"] += 1

        #print(self.CURRENT_INFO)
        for i in self.CURRENT_INFO:
            # print(i, type(i))
            #print(self.CURRENT_INFO[i]["counts"])
            if(self.CURRENT_INFO[i]["counts"] >= self.CONCURRENCY_ALLOWED):
                print('detect a attack ip', i)
                self.BlOCKING_IP.add(i)
        # for item in self.BlOCKING_IP:
        #     print(self.BlOCKING_IP)

    def getData(self, info):
        pattern = re.compile("\s+")     # 匹配多个空白字符
        strArr = bytes.decode(info, "GB2312").split('\n')
        # info = strArr1[8]       # 接收的分段信息所在行      
        item = pattern.split(strArr[8] )   
        # print(item) # ['', '接收的分段', '=', '1525721', '']
        return int(item[3]) # 返回接收的分段数
        
    def flowCheck(self):
        pipe1_v4 = Popen("netstat -nsp TCP", shell=True, bufsize=1024, stdout=PIPE).stdout
        info1_v4 = pipe1_v4.read()  # 获取bytes串
        pipe1_v6 = Popen("netstat -nsp TCPv6", shell=True, bufsize=1024, stdout=PIPE).stdout
        info1_v6 = pipe1_v6.read()

        time.sleep(1)   # 两次扫描间隔一秒以便统计每秒的速率

        pipe2_v4 = Popen("netstat -nsp TCP", shell=True, bufsize=1024, stdout=PIPE).stdout
        info2_v4 = pipe2_v4.read()
        pipe2_v6 = Popen("netstat -nsp TCPv6", shell=True, bufsize=1024, stdout=PIPE).stdout
        info2_v6 = pipe2_v6.read()
        tmp1_v4 = self.getData(info1_v4)  # 第一次扫描记录数据包数目
        tmp1_v6 = self.getData(info1_v6)
        tmp2_v4 = self.getData(info2_v4)  # 第二次扫描记录数据包数目
        tmp2_v6 = self.getData(info2_v6)
        counts_ipv4 = tmp2_v4 - tmp1_v4   # 两者相减得到ipv4接收的分段数目
        self.CURRENT_FLOW["Ipv4"] = counts_ipv4
        counts_ipv6 = tmp2_v6 - tmp1_v6
        self.CURRENT_FLOW["Ipv6"] = counts_ipv6
        self.TOTOAL_FLOW += (counts_ipv4 +counts_ipv6)

        #print(counts_ipv4, counts_ipv6)



def main():
    ddos = DDosCheck()
    # ddos.setMaxConcurrency(10)
    # ddos.connectCheck()
    ddos.flowCheck()

if(__name__ == '__main__'):
    main()