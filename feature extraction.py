#!/usr/bin/env python
# coding=utf-8
# 读取pcap文件，解析相应的信息，为了在记事本中显示的方便，把二进制的信息

import struct
import pandas as pd
import time
import numpy as np


# 读取pcap文件中的所有数据，返回结果为[{},{},{'':'','':''}]
def rdpcap():
    fpcap = open('doubai.pcap', 'rb')
    ftxt = open('result.txt', 'w', encoding="utf-8")

    string_data = fpcap.read()

    # pcap文件包头解析
    pcap_header = {}
    pcap_header['magic_number'] = string_data[0:4]
    pcap_header['version_major'] = string_data[4:6]
    pcap_header['version_minor'] = string_data[6:8]
    pcap_header['thiszone'] = string_data[8:12]
    pcap_header['sigfigs'] = string_data[12:16]
    pcap_header['snaplen'] = string_data[16:20]
    pcap_header['linktype'] = string_data[20:24]
    # 把pacp文件头信息写入result.txt
    ftxt.write("Pcap文件的包头内容如下： \n")
    for key in ['magic_number', 'version_major', 'version_minor', 'thiszone',
                'sigfigs', 'snaplen', 'linktype']:
        ftxt.write(key + " : " + repr(pcap_header[key]) + '\n')

    # pcap文件的数据包解析
    step = 0
    packet_num = 0
    packet_data = []

    pcap_packet_header = {}
    i = 24

    while (i < len(string_data)):
        # 数据包头各个字段
        pcap_packet_header['GMTtime'] = string_data[i:i + 4]
        pcap_packet_header['MicroTime'] = string_data[i + 4:i + 8]
        pcap_packet_header['caplen'] = string_data[i + 8:i + 12]
        pcap_packet_header['len'] = string_data[i + 12:i + 16]
        # 求出此包的包长len
        packet_len = struct.unpack('I', pcap_packet_header['len'])[0]
        # 写入此包数据
        packet_data.append(string_data[i + 16:i + 16 + packet_len])
        i = i + packet_len + 16
        packet_num += 1

    all_pcap_data = []

    # 把pacp文件里的数据包信息写入result.txt
    for i in range(packet_num):
        # 先写每一包的包头

        ftxt.write("这是第" + str(i) + "包数据的包头和数据：" + '\n')

        pcap_data = {}

        for key in ['GMTtime', 'MicroTime', 'caplen', 'len']:
            ftxt.write(key + ' : ' + repr(pcap_packet_header[key]) + '\n')

        # 再写数据部分

        data = packet_data[i]
        # print(data)
        # ftxt.write('此包的数据内容' + repr(packet_data[i]) + '\n')
        ftxt.write('此包的数据内容' + repr(data) + '\n')

        pcap_data["id"] = i + 1
        pcap_data["GMTtime"] = repr(pcap_packet_header["GMTtime"])
        pcap_data["MicroTime"] = repr(pcap_packet_header["MicroTime"])
        pcap_data["caplen"] = repr(pcap_packet_header["caplen"])
        pcap_data["len"] = repr(pcap_packet_header["len"])
        pcap_data["data"] = data
        all_pcap_data.append(pcap_data)

    ftxt.write('一共有' + str(packet_num) + "包数据" + '\n')

    ftxt.close()
    fpcap.close()
    return all_pcap_data


# all_flows_data = rdpcap()
# print(type(all_flows_data[0]["data"][0:10]))
# print(len(all_flows_data))


# 提取每个数据包的五元组，返回结果是一个列表
def dealdata():
    all_flows_data = rdpcap()
    all_five_tuple = []
    for i in range(len(all_flows_data)):
        features = []
        dmac = all_flows_data[i]["data"][0:12]
        smac = all_flows_data[i]["data"][12:24]
        mactype = all_flows_data[i]["data"][24:28]
        ipversion = all_flows_data[i]["data"][28:29]
        ip_header_length = all_flows_data[i]["data"][29:30]
        tos = all_flows_data[i]["data"][30:32]
        ip_length = all_flows_data[i]["data"][32:36]
        identitication = all_flows_data[i]["data"][36:40]
        # tag = all_flows_data[i]["data"][72:75]
        # displacement = all_flows_data[i]["data"][75:88]
        ttl = all_flows_data[i]["data"][44:46]
        pro = all_flows_data[i]["data"][46:48]
        header_sum = all_flows_data[i]["data"][48:52]
        srcip = all_flows_data[i]["data"][52:60]
        # srcip = iptransform(srcip)
        dstip = all_flows_data[i]["data"][60:68]
        # dstip = iptransform(dstip)

        if (int(ip_header_length) == 5):
            five_tuple = []
            sport = all_flows_data[i]["data"][68:72]
            # sport = porttransform(sport)
            dport = all_flows_data[i]["data"][72:76]
            # dport = porttransform(dport)
            # print(str(sport)+"----->"+str(dport))
            if (int(pro) == 6):
                xuhao = all_flows_data[i]["data"][76:84]
                qurenhao = all_flows_data[i]["data"][84:92]
                biaozhiwei = all_flows_data[i]["data"][92:96]
                biaozhiwei = hex2bin16bit(biaozhiwei)
                shujupianyi = biaozhiwei[0:4]
                URG = biaozhiwei[10]
                ACK = biaozhiwei[11]
                PSH = biaozhiwei[12]
                RST = biaozhiwei[13]
                SYN = biaozhiwei[14]
                FIN = biaozhiwei[15]
                chuangkou = all_flows_data[i]["data"][96:100]
                jianyanhe = all_flows_data[i]["data"][100:108]
                jinji = all_flows_data[i]["data"][108:116]
            if (int(pro) == 11):
                udp_length = all_flows_data[i]["data"][76:80]
                udp_check = all_flows_data[i]["data"][80:84]
            five_tuple = str(pro) + str(srcip) + str(dstip) + str(sport) + str(dport)
            all_five_tuple.append(five_tuple)

        else:
            print("第" + str(i + 1) + "ip报头不是20字节，需要重新处理")
    return all_five_tuple


# 提取pcap包中的所有流,flow的形式：{"":["",""], "五元组":["数据","数据"]}
def extractflow():
    flow = {}
    all_five_tuple = dealdata()
    all_pcap_data = rdpcap()
    for i in range(len(all_five_tuple)):
        if all_five_tuple[i] not in flow.keys():
            flow[all_five_tuple[i]] = []
    for i in range(len(all_five_tuple)):
        if all_five_tuple[i] in flow.keys():
            flow[all_five_tuple[i]].append(all_pcap_data[i]["data"])  # 如果提取完整流的话去掉data
    # print(flow)
    # print(flow['060a00030f968a780183480050'])
    return flow


# 将16进制的ip地址转化为点分十进制
def iptransform(ip):
    ip1 = int(ip[0:2], 16)
    ip2 = int(ip[2:4], 16)
    ip3 = int(ip[4:6], 16)
    ip4 = int(ip[6:8], 16)
    ip_dec = str(ip1) + "." + str(ip2) + "." + str(ip3) + "." + str(ip4)
    return ip_dec


# 将16进制的端口号转化为10进制
def porttransform(port):
    port = int(port[0:4], 16)
    return port


# 将16进制的字符串转化为2进制
def hex2bin16bit(str1):
    str2 = ""
    a = {'1': "0001", '2': "0010", '3': "0011", '4': "0100", '5': "0101", '6': "0110", '7': "0111", '8': "1000",
         '9': "1001", 'b': "1010", 'c': "1011", 'd': "1100", 'a': "1001", 'e': "1110", 'f': "1111", '0': "0000"}
    for i in range(len(str1)):
        str2 = str2 + a[str1[i]]
    return str2


def extracinformation():
    flow = extractflow()
    pro = []
    srcip = []
    dstip = []
    sport = []
    dport = []

    wuyuanzu = list(flow.keys())
    print(len(wuyuanzu))

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

        # print("第"+str(i+1)+"流："+pro[i]+"\t"+srcip[i]+"\t"+dstip[i]+"\t"+str(sport[i])+"\t"+str(dport[i]))

    return pro, srcip, dstip, sport, dport
    # print(srcip)


def extracinformation_1():
    flow = extractflow()
    min_data_ip = []
    q1_data_ip = []
    med_data_ip = []
    mean_data_ip = []
    q3_data_ip = []
    max_data_ip = []
    var_data_ip = []

    min_data_wire = []
    q1_data_wire = []
    med_data_wire = []
    mean_data_wire = []
    q3_data_wire = []
    max_data_wire = []
    var_data_wire = []

    for item in flow:
        # print("-" * 20)
        ip_length = []

        for i in range(len(flow[item])):
            ip_length1 = flow[item][i][32:36]
            ip_length1 = int(ip_length1, 16)
            ip_length.append(ip_length1)

        ip_length = sorted(ip_length)

        min_data_ip1 = ip_length[0]
        min_data_ip.append(min_data_ip1)
        max_data_ip1 = ip_length[len(ip_length) - 1]
        max_data_ip.append(max_data_ip1)
        mean_data_ip1 = np.mean(ip_length)
        mean_data_ip1 = round(mean_data_ip1)
        mean_data_ip.append(mean_data_ip1)
        var_data_ip1 = np.var(ip_length)
        var_data_ip1 = round(var_data_ip1)
        var_data_ip.append(var_data_ip1)

        min_data_wire1 = ip_length[0] + 18
        min_data_wire.append(min_data_wire1)
        max_data_wire1 = ip_length[len(ip_length) - 1] + 18
        max_data_wire.append(max_data_wire1)
        mean_data_wire1 = np.mean(ip_length)
        mean_data_wire1 = round(mean_data_wire1) + 18
        mean_data_wire.append(mean_data_wire1)
        var_data_wire1 = np.var(ip_length)
        var_data_wire1 = round(var_data_wire1)
        var_data_wire.append(var_data_wire1)

        if (len(ip_length) % 4) == 3 or len(ip_length) == 1:
            q1_data_ip1 = ip_length[len(ip_length) // 4]
            q1_data_wire1 = ip_length[len(ip_length) // 4]
        else:
            q = (len(ip_length) + 1) / 4 - (len(ip_length) // 4)
            q1_data_ip1 = ip_length[len(ip_length) // 4] * q + ip_length[len(ip_length) // 4 + 1] * (1 - q)
            q1_data_ip1 = round(q1_data_ip1)
            q1_data_wire1 = round(q1_data_ip1) + 18
        q1_data_ip.append(q1_data_ip1)
        q1_data_wire.append(q1_data_wire1)

        if (len(ip_length) % 2) == 1:
            med_data_ip1 = ip_length[len(ip_length) // 2]
        else:
            med_data_ip1 = (ip_length[len(ip_length) // 2 - 1] + ip_length[len(ip_length) // 2]) / 2
            med_data_ip1 = round(med_data_ip1)

        med_data_wire1 = med_data_ip1 + 18
        med_data_ip.append(med_data_ip1)
        med_data_wire.append(med_data_wire1)

        if (len(ip_length) % 4) == 3 or len(ip_length) == 1:
            if (len(ip_length) % 4) == 3:
                p = int((len(ip_length) + 1) * 3 / 4 - 1)
                q3_data_ip1 = ip_length[p]
            else:
                q3_data_ip1 = ip_length[0]
        else:
            q = (len(ip_length) + 1) / 4 - (len(ip_length) // 4)
            q3_data_ip1 = ip_length[len(ip_length) // 4] * q + ip_length[len(ip_length) // 4 + 1] * (1 - q)
            q3_data_ip1 = round(q3_data_ip1)

        q3_data_wire1 = q3_data_ip1 + 18
        q3_data_ip.append(q3_data_ip1)
        q3_data_wire.append(q3_data_wire1)
        # print(ip_length)

    return min_data_ip, q1_data_ip, med_data_ip, mean_data_ip, q3_data_ip, max_data_ip, var_data_ip, min_data_wire, q1_data_wire, med_data_wire, mean_data_wire, q3_data_wire, max_data_wire, var_data_wire
    # print(ip_length)
    # print(flow[item][i][0:10])

    # for j in range(len(flow[i].values())):
    #     print(flow[i][j])


def extracinformation_2():
    flow = extractflow()

    min_data_control = []
    q1_data_control = []
    med_data_control = []
    mean_data_control = []
    q3_data_control = []
    max_data_control = []
    var_data_control = []

    total_packets = []
    ack_pkts_sent = []
    pure_acks_sent = []
    actual_data_bytes = []
    pushed_data_pkts = []
    SYN_pkts_sent = []
    FIN_pkts_sent = []
    urgent_data_pkts = []


    for item in flow:
        # print("-" * 20)
        ipheader_length = []
        ACK_sum = 0
        pure_ack_sum = 0
        actual_data_sum = 0
        pushed_data_sum =0
        SYN_pkts_sum = 0
        FIN_pks_sum = 0
        urgent_data_sum = 0

        for i in range(len(flow[item])):
            ipheader_length1 = flow[item][i][29:30]
            ipheader_length1 = int(ipheader_length1, 16)
            ipheader_length.append(ipheader_length1)

            if int(item[0:2]) == 6:
                biaozhiwei = flow[item][i][92:96]
                biaozhiwei = hex2bin16bit(biaozhiwei)

                URG = biaozhiwei[10]
                ACK = biaozhiwei[11]
                PSH = biaozhiwei[12]
                RST = biaozhiwei[13]
                SYN = biaozhiwei[14]
                FIN = biaozhiwei[15]
                ip_length = flow[item][i][32:36]
                ip_length = int(ip_length,16)

                if len(flow[item][i])>116:
                    actual_data_sum = actual_data_sum + 1

                if int(ACK) == 1:
                    ACK_sum = ACK_sum + 1

                if int(SYN) == 1:
                    SYN_pkts_sum = SYN_pkts_sum +1

                if int(PSH) ==1:
                    pushed_data_sum = pushed_data_sum + 1

                if int(FIN) ==1:
                    FIN_pks_sum = FIN_pks_sum +1

                if int(URG) == 1:
                    urgent_data_sum = urgent_data_sum +1




                if len(flow[item][i])==116 and ACK==1 and SYN==0 and FIN==0 and RST ==0:
                    pure_ack_sum = pure_ack_sum +1


                if int(SYN)==0 and int(FIN)==0 and int(RST)==0 and int(ACK)==1 and len(flow[item][i])==108 and ip_length ==40:
                    pure_ack_sum = pure_ack_sum +1



        ipheader_length = sorted(ipheader_length)
        total_packets1 = len(flow[item])
        total_packets.append(total_packets1)
        ack_pkts_sent.append(ACK_sum)
        pure_acks_sent.append(pure_ack_sum)
        actual_data_bytes.append(actual_data_sum)
        pushed_data_pkts.append(pushed_data_sum)
        SYN_pkts_sent.append(SYN_pkts_sum)
        FIN_pkts_sent.append(FIN_pks_sum)
        urgent_data_pkts.append(urgent_data_sum)


        min_data_control1 = ipheader_length[0]
        min_data_control.append(min_data_control1)
        max_data_control1 = ipheader_length[len(ipheader_length) - 1]
        max_data_control.append(max_data_control1)
        mean_data_control1 = np.mean(ipheader_length)
        mean_data_control1 = round(mean_data_control1)
        mean_data_control.append(mean_data_control1)
        var_data_control1 = np.var(ipheader_length)
        var_data_control1 = round(var_data_control1)
        var_data_control.append(var_data_control1)



        if (len(ipheader_length) % 4) == 3 or len(ipheader_length) == 1:
            q1_data_control1 = ipheader_length[len(ipheader_length) // 4]
            # q1_data_wire1 = ipheader_length[len(ipheader_length) // 4]
        else:
            q = (len(ipheader_length) + 1) / 4 - (len(ipheader_length) // 4)
            q1_data_control1 = ipheader_length[len(ipheader_length) // 4] * q + ipheader_length[
                len(ipheader_length) // 4 + 1] * (1 - q)
            q1_data_control1 = round(q1_data_control1)
            # q1_data_wire1 = round(q1_data_ip1) + 18
        q1_data_control.append(q1_data_control1)
        # q1_data_wire.append(q1_data_wire1)

        if (len(ipheader_length) % 2) == 1:
            med_data_control1 = ipheader_length[len(ipheader_length) // 2]
        else:
            med_data_control1 = (ipheader_length[len(ipheader_length) // 2 - 1] + ipheader_length[
                len(ipheader_length) // 2]) / 2
            med_data_control1 = round(med_data_control1)

        # med_data_wire1 = med_data_control1 + 18
        med_data_control.append(med_data_control1)
        # med_data_wire.append(med_data_wire1)

        if (len(ipheader_length) % 4) == 3 or len(ipheader_length) == 1:
            if (len(ipheader_length) % 4) == 3:
                p = int((len(ipheader_length) + 1) * 3 / 4 - 1)
                q3_data_control1 = ipheader_length[p]
            else:
                q3_data_control1 = ipheader_length[0]
        else:
            q = (len(ipheader_length) + 1) / 4 - (len(ipheader_length) // 4)
            q3_data_control1 = ipheader_length[len(ipheader_length) // 4] * q + ipheader_length[
                len(ipheader_length) // 4 + 1] * (1 - q)
            q3_data_control1 = round(q3_data_control1)

        q3_data_wire1 = q3_data_control1 + 18
        q3_data_control.append(q3_data_control1)
        # q3_data_wire.append(q3_data_wire1)

    # print(ack_pkts_sent)
    # print(len(ack_pkts_sent))

    return min_data_control, q1_data_control, med_data_control, mean_data_control, q3_data_control, max_data_control, var_data_control, total_packets, ack_pkts_sent, pure_acks_sent, actual_data_bytes, pushed_data_pkts, SYN_pkts_sent, FIN_pkts_sent, urgent_data_pkts


def extracinformation_3():
    flow = extractflow()
    max_win_adv = []
    min_win_adv = []
    zero_win_adv = []
    avg_win_adv = []
    for item in flow:
        chuangkou = []
        if int(item[0:2]) == 6:
            zero_win_sum = 0
            for i in range(len(flow[item])):

                chuangkou1 = flow[item][i][96:100]
                chuangkou1 = int(chuangkou1,16)
                chuangkou.append(chuangkou1)

                if chuangkou1==0:
                    zero_win_sum = zero_win_sum +1

            chuangkou = sorted(chuangkou)
            avg_win_adv1 = np.mean(chuangkou)
            avg_win_adv1 = round(avg_win_adv1)
            avg_win_adv.append(avg_win_adv1)

            min_win_adv1 = chuangkou[0]
            min_win_adv.append(min_win_adv1)
            max_win_adv1 = chuangkou[len(chuangkou) - 1]
            max_win_adv.append(max_win_adv1)
            zero_win_adv.append(zero_win_sum)
        else:
            max_win_adv.append("-")
            min_win_adv.append("-")
            zero_win_adv.append("-")
            avg_win_adv.append("-")

    return max_win_adv, min_win_adv, zero_win_adv, avg_win_adv



def wcsv():
    pro, srcip, dstip, sport, dport = extracinformation()
    min_data_ip, q1_data_ip, med_data_ip, mean_data_ip, q3_data_ip, max_data_ip, var_data_ip, min_data_wire, q1_data_wire, med_data_wire, mean_data_wire, q3_data_wire, max_data_wire, var_data_wire = extracinformation_1()
    min_data_control, q1_data_control, med_data_control, mean_data_control, q3_data_control, max_data_control, var_data_control, total_packets, ack_pkts_sent, pure_acks_sent, actual_data_bytes, pushed_data_pkts, SYN_pkts_sent, FIN_pkts_sent, urgent_data_pkts = extracinformation_2()
    max_win_adv, min_win_adv, zero_win_adv, avg_win_adv = extracinformation_3()
    dataframe = pd.DataFrame(
        {'protocol': pro, ' srcip': srcip, ' dstip': dstip, " sport": sport, " dport": dport,
         " min_data_ip": min_data_ip, " q1_data_ip": q1_data_ip,
         " med_data_ip": med_data_ip, "mean_data_ip": mean_data_ip, "q3_data_ip": q3_data_ip,
         " max_data_ip": max_data_ip, "var_data_ip": var_data_ip,
         " min_data_wire": min_data_wire, " q1_data_wire": q1_data_wire,
         " med_data_wire": med_data_wire, "mean_data_wire": mean_data_wire, "q3_data_wire": q3_data_wire,
         " max_data_wire": max_data_wire, "var_data_wire": var_data_wire, "min_data_control": min_data_control,
         "q1_data_control": q1_data_control, "med_data_control": med_data_control,
         "mean_data_control": mean_data_control, "q3_data_control": q3_data_control,
         "max_data_control": max_data_control, "var_data_control": var_data_control, "total_packets": total_packets,
         "ack_pkts_sent": ack_pkts_sent, "pure_acks_sent":pure_acks_sent, "actual_data_bytes": actual_data_bytes, "pushed_data_pkts":pushed_data_pkts, "SYN_pkts_sent": SYN_pkts_sent, "FIN_pkts_sent": FIN_pkts_sent, "urgent_data_pkts":urgent_data_pkts,"max_win_adv":max_win_adv, "min_win_adv": min_win_adv,"zero_win_adv":zero_win_adv, "avg_win_adv":avg_win_adv
         })
    dataframe.to_csv('doubai.csv', index=False, sep=' ')


wcsv()

# extracinformation_3()
