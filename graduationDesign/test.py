# import os
# print(os.path.join(os.getcwd(), 'weakpasswd_part.txt'))

# f = open(r'D:\Crs chen\2020_Graduation\graduationDesign\pwd.txt', 'r')
# for line in f.readlines():
#     print(line)
# f.close()
# from subprocess import Popen, PIPE
# import chardet
# pipe = Popen("netstat -vn", shell=True, bufsize=1024, stdout=PIPE).stdout
# info = pipe.read()  # 获取bytes串
# ret = chardet.detect(info)
# print(ret)

print("{:&>20d}".format(20))