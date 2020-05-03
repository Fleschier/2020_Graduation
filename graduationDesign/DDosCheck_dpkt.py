coding='utf-8'

import dpkt
import socket
import optparse

THRESH = 1000  # 阈值

def findDownload(pcap):
    for(ts, buf) in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            src = socket.inet_ntoa(ip.src)
            # 获取TCP数据
            tcp = ip.data
            # 解析TCP中的上层协议HTTP的请求
            http = dpkt.http.Request(tcp.data)
            # 若是GET方法，且请求行中包含“.zip”和“loic”字样则判断为下载LOIC
            if(http.method == 'GET'):
                uri = http.uri.lower()
                if('.zip' in uri and 'loic' in uri):
                    print('!' + src + "Downloaded LOIC")
        except:
            pass

def findHivemind(pcap):
    for (ts, buf) in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            tcp = ip.data
            dport = tcp.dport
            sport = tcp.sport
            # 若目标端口为6667且含有“!lazor”指令，则确定是某个成员提交一个攻击指令
            if(dport == 6667):
                if('!lazor' in tcp.data.lower()):
                    print("[!]DDos Hivemind issued by:" + src)
                    print('[+] Target CMD:' + tcp.data)
            # 若源端口为6667且含有“!lazor”指令，则确定是服务器在向HIVE中的成员发布攻击的消息
            if(sport == 6667):
                if('!lazor' in tcp.data.lower()):
                    print("[!]DDos Hivemind issued by:" + src)
                    print('[+] Target CMD:' + tcp.data)
        except:
            pass

def findAttack(pcap):
    pktCount = {}
    for (ts, buf) in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            tcp = ip.data
            dport = tcp.dport
            # 累计各个src地址对目标地址80端口访问的次数
            if(dport == 80):
                stram = src + ':' + dst
                if(pktCount.has_key(stram)):
                    pktCount[stram] = pktCount[stram] + 1
                else:
                    pktCount[stram] = 1
        except:
            pass

    for stream in pktCount:
        pktsSent = pktCount[stream]
        # 若超过设置检测的阈值，则判断为进行DDoS攻击
        if pktsSent > THRESH:
            src = stream.split(':')[0]
            dst = stream.split(':')[1]
            print( '[+] ' + src + ' attacked ' + dst + ' with ' + str(pktsSent) + ' pkts.')

def main():
    parser = optparse.OptionParser("[*]Usage python findDDoS.py -p <pcap file> -t <thresh>")
    parser.add_option('-p', dest='pcapFile', type='string', help='specify pcap filename')
    parser.add_option('-t', dest='thresh', type='int', help='specify threshold count ')
    (options, args) = parser.parse_args()
    if options.pcapFile == None:
        print(parser.usage)
        exit(0)
    if options.thresh != None:
        THRESH = options.thresh
        pcapFile = options.pcapFile
    # 这里的pcap文件解析只能调用一次，注释掉另行修改
    # f = open(pcapFile)
    # pcap = dpkt.pcap.Reader(f)
    # findDownload(pcap)
    # findHivemind(pcap)
    # findAttack(pcap)
    with open(pcapFile, 'r') as f:
        pcap = dpkt.pcap.Reader(f)
        findDownload(pcap)
    with open(pcapFile, 'r') as f:
        pcap = dpkt.pcap.Reader(f)
        findHivemind(pcap)
    with open(pcapFile, 'r') as f:
        pcap = dpkt.pcap.Reader(f)
        findAttack(pcap)

if(__name__ == '__main__'):
    main()