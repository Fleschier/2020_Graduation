from subprocess import Popen, PIPE
import re
import time

import dpkt
import socket
import optparse
"""
netstat [选项] 
 
命令中各选项的含义如下： 
 
-a 显示所有socket，包括正在监听的。 
-c 每隔1秒就重新显示一遍，直到用户中断它。 
-i 显示所有网络接口的信息，格式同“ifconfig -e”。 
-n 以网络IP地址代替名称，显示出网络连接情形。 
-r 显示核心路由表，格式同“route -e”。 
-t 显示TCP协议的连接情况。 
-u 显示UDP协议的连接情况。 
-v 显示正在进行的工作。 
 
-A 显示任何关联的协议控制块的地址。主要用于调试 
-a 显示所有套接字的状态。在一般情况下不显示与服务器进程相关联的套接字 
-i 显示自动配置接口的状态。那些在系统初始引导后配置的接口状态不在输出之列 
-m 打印网络存储器的使用情况 
-n 打印实际地址，而不是对地址的解释或者显示主机，网络名之类的符号 
-r 打印路由选择表 
-f address -family对于给出名字的地址簇打印统计数字和控制块信息。到目前为止，唯一支持的地址簇是inet 
-I interface 只打印给出名字的接口状态 
-p protocol-name 只打印给出名字的协议的统计数字和协议控制块信息 
-s 打印每个协议的统计数字 
-t 在输出显示中用时间信息代替队列长度信息。 
 
netstat命令的列标题 
Name 接口的名字 
Mtu 接口的最大传输单位 
Net/Dest 接口所在的网络 
Address 接口的IP地址 
Ipkts 接收到的数据包数目 
Ierrs 接收到时已损坏的数据包数目 
Opkts 发送的数据包数目 
Oeers 发送时已损坏的数据包数目 
Collisions 由这个接口所记录的网络冲突数目 
 
netstat的一些常用选项： 
netstat -s--本选项能够按照各个协议分别显示其统计数据。如果你的应用程序（如Web浏览器）运行速度比较慢，或者不能显示Web页之类的数据，那么你就可以用本选项来查看一下所显示的信息。你需要仔细查看统计数据的各行，找到出错的关键字，进而确定问题所在。 
netstat -e--本选项用于显示关于以太网的统计数据。它列出的项目包括传送的数据报的总字节数、错误数、删除数、数据报的数量和广播的数量。这些统计数据既有发送的数据报数量，也有接收的数据报数量。这个选项可以用来统计一些基本的网络流量）。 
netstat -r--本选项可以显示关于路由表的信息，类似于后面所讲使用route print命令时看到的 信息。除了显示有效路由外，还显示当前有效的连接。 
netstat -a--本选项显示一个所有的有效连接信息列表，包括已建立的连接（ESTABLISHED），也包括监听连接请求（LISTENING）的那些连接。 
bnetstat -n--显示所有已建立的有效连接。 
« AWKPHP经典 »netstat -an中state含义 
 
 
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
class DDosCheck():
    CONCURRENCY_ALLOWED = 30
    OUTDATE_TIME = 86400

    # 使用windows的 netstat命令来查询所有端口的状态