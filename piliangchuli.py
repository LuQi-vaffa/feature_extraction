import os
from extraction import rdpcap,dealdata, extracinformation, extracinformation_1, extracinformation_2, \
    extracinformation_3,iptransform,porttransform
import pandas as pd

path = r"E:\pycharm project\feature extracton\pcap包" #文件夹目录

files= os.listdir(path) #得到文件夹下的所有文件名称

txts = []

for file in files: #遍历文件夹
    position = path+'\\'+ file #构造绝对路径，"\\"，其中一个'\'为转义符
    # print (position)
    all_flows_data_pcap =rdpcap(position)
    flow = {}
    all_five_tuple = dealdata(all_flows_data_pcap)
    for i in range(len(all_five_tuple)):
        if all_five_tuple[i] not in flow.keys():
            flow[all_five_tuple[i]] = []
    for i in range(len(all_five_tuple)):
        if all_five_tuple[i] in flow.keys():
            flow[all_five_tuple[i]].append(all_flows_data_pcap[i]["data"])  # 如果提取完整流的话去掉data

    pro = []
    srcip = []
    dstip = []
    sport = []
    dport = []

    wuyuanzu = list(flow.keys())
    # print(len(wuyuanzu))

    for i in range(len(wuyuanzu)):
        pro1 = wuyuanzu[i][0:2]
        if int(pro1) == 6:
            pro.append("tcp")
        if int(pro1) == 11:
            pro.append("udp")
        srcip1 = wuyuanzu[i][2:10]
        srcip1 = iptransform(srcip1)
        srcip.append(srcip1)
        dstip1 = wuyuanzu[i][10:18]
        dstip1 = iptransform(dstip1)
        dstip.append(dstip1)
        sport1 = wuyuanzu[i][18:22]
        sport1 = porttransform(sport1)
        sport.append(sport1)
        dport1 = wuyuanzu[i][22:26]
        dport1 = porttransform(dport1)
        dport.append(dport1)




    comment = []
    comment.append("-"*100)

    df = pd.DataFrame(comment)
    df.to_csv('features.csv', mode='a')

    dataframe = pd.DataFrame(
        {'protocol': pro, ' srcip': srcip, ' dstip': dstip, " sport": sport, " dport": dport,

         })
    dataframe.to_csv('features.csv', index=False, sep=' ', mode='a')





