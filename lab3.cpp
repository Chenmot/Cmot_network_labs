#include <iostream>
#include "pcap.h"
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <vector>
#include <cstring>
#include <string>

using namespace std;
//报文格式
#pragma pack(1)//以1byte方式对齐

typedef struct FrameHeader_t {//帧首部
    BYTE DesMAC[6];//目的地址
    BYTE SrcMAC[6];//源地址
    WORD FrameType;//帧类型
}FrameHeader_t;

typedef struct ARPFrame_t {//IP首部
    FrameHeader_t FrameHeader;
    WORD HardwareType;//硬件类型
    WORD ProtocolType;//协议类型
    BYTE HLen;//硬件地址长度
    BYTE PLen;//协议地址长度
    WORD Operation;//操作类型
    BYTE SendHa[6];//发送方MAC地址
    DWORD SendIP;//发送方IP地址
    BYTE RecvHa[6];//接收方MAC地址
    DWORD RecvIP;//接收方IP地址
}ARPFrame_t;

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    vector<string> ip;
    // 获取可用网络设备列表
    pcap_if_t* alldevs;
    pcap_if_t* d;

    ARPFrame_t ARPFrame;
    ARPFrame_t* IPPacket;
    pcap_pkthdr* pkt_header;
    const u_char* pkt_data;
    pcap_addr_t* a;

    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
        cerr << "查找网卡时出错: " << errbuf << endl;
        return 1;
    }
    int count = 0;
    d = alldevs;
    while (d != NULL) {
        count++;
        cout << "网卡" << count << "： " << d ->name << endl;
        cout << "   描述信息为：" << d ->description << endl;
        for (pcap_addr* a = d->addresses; a != nullptr; a = a->next)//判断是否有网络接口的地址信息
        {
            if (((struct sockaddr_in*)a->addr)->sin_family == AF_INET && a->addr)
            {//打印ip地址
                std::cout << "   IP地址为：" << inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr) << endl;
                std::cout << "   子网掩码为：" << inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr) << endl;

                //将ip列表存入数组，方便后面选择目的ip和组装数据包
                ip.push_back(inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
            }
            else
                ip.push_back("00.00.00.00");
        }
        std::cout << endl;
        d = d ->next;
    }
   
    for (int i = 0; i < ip.size(); ++i) {
        std::cout << "IP[" << i + 1 << "]: " << ip[i] << endl;
    }

    int selected_device;
    std::cout << "选择一个网卡设备（1-" << count << "）: ";
    cin >> selected_device;

    pcap_if_t*  device = alldevs;
    for (int i = 1; i < selected_device; i++) {
        device = device->next;
    }

    pcap_t* handle = pcap_open(device->name, 1024, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
    if (handle == NULL) {
        cerr << "打开设备时出错: " << errbuf << endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

    u_int netmask;
    netmask = ((sockaddr_in*)(device->addresses->netmask))->sin_addr.S_un.S_addr;
    bpf_program fcode;
    char packet_filter[] = "ether proto \\arp";
    if (pcap_compile( handle, &fcode, packet_filter, 1, netmask) < 0) {
        std::cout << "无法编译数据包过滤器" << endl;
        pcap_freealldevs(alldevs);
        return 1;
    }
    if (pcap_setfilter(handle, &fcode) < 0) {
        std::cout << "过滤器设置错误" << endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

   

    std::cout << "输入想要请求的IP地址：";
    char addr[15];
    cin >> addr;

    //设置目的MAC地址为广播地址
    for (int i = 0; i < 6; i++)
        ARPFrame.FrameHeader.DesMAC[i] = 0xFF;//表示广播

    //设置源MAC地址为本机网卡的MAC地址
    for (int i = 0; i < 6; i++)
        ARPFrame.FrameHeader.SrcMAC[i] = 0x66;

    //将接收方的硬件地址（RecvHa）设置为0，表示目的地址未知
    for (int i = 0; i < 6; i++)
        ARPFrame.RecvHa[i] = 0;//表示目的地址未知

    //将发送方的硬件地址（SendHa）设置为本机网卡的MAC地址
    for (int i = 0; i < 6; i++)
        ARPFrame.SendHa[i] = 0x66;

    ARPFrame.FrameHeader.FrameType = htons(0x806);//帧类型为ARP
    ARPFrame.HardwareType = htons(0x0001);//硬件类型为以太网
    ARPFrame.ProtocolType = htons(0x0800);//协议类型为IP
    ARPFrame.HLen = 6;//硬件地址长度为6
    ARPFrame.PLen = 4;//协议地址长为4
    ARPFrame.Operation = htons(0x0001);//操作为ARP请求

    std::cout << "选择连接方式（本地0，远程1）：";
    int model;
    cin >> model;

    if (model == 0) {
        ARPFrame.SendIP = htonl(0x70707070);//本机网卡上绑定的IP地址
        //循环遍历网络设备的地址信息，找到 IPv4 地址，并将该地址设置为 ARP 数据包的接收方IP地址。
        for (a = device->addresses; a != NULL; a = a->next)
        {
            if (a->addr->sa_family == AF_INET)
            {
                ARPFrame.RecvIP = inet_addr(inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr));
            }
        }

    }
    else {
        ARPFrame.SendIP = htonl(0x70707070);

        for (a = device->addresses; a != NULL; a = a->next)
        {
            if (a->addr->sa_family == AF_INET)
            {
                ARPFrame.RecvIP = inet_addr(inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr));
            }
        }

        pcap_sendpacket(handle, (u_char*)&ARPFrame, sizeof(ARPFrame_t));

        while (true)
        {
            int rtn = pcap_next_ex(handle, &pkt_header, &pkt_data);
            if (rtn == -1) {
                return 1;
            }
            else if (rtn == 0) {
            }
            else {
                IPPacket = (ARPFrame_t*)pkt_data;
                if (ntohs(IPPacket->FrameHeader.FrameType) == 0x806) {
                    if (memcmp(IPPacket->FrameHeader.SrcMAC, ARPFrame.FrameHeader.SrcMAC, 6) != 0) {
                        break;  // 找到 MAC 地址，退出
                    }
                }
            }
        }

        ARPFrame.SendIP = IPPacket->SendIP;//将本机IP赋值给数据报的源IP
        ARPFrame.RecvIP = inet_addr(addr);
        
        for (int i = 0; i < 6; i++)
        {
            ARPFrame.SendHa[i] = ARPFrame.FrameHeader.SrcMAC[i] = IPPacket->SendHa[i];
        }
    }


    pcap_sendpacket(handle, (u_char*)&ARPFrame, sizeof(ARPFrame_t));

    std::cout << "ARP请求发送成功" << endl;

    while (true)
    {
       int rtn = pcap_next_ex(handle, &pkt_header, &pkt_data);//pcap_next_ex 用于捕获下一个数据包
       if (rtn == -1) {
           std::cout << "捕获数据包错误：" << errbuf << endl;
           return 1;
       }
       else if (rtn == 0) {
           std::cout << "没有捕获到有效数据包" << endl;
       }
       else {
           IPPacket = (ARPFrame_t*)pkt_data;
           if (ntohs(IPPacket->FrameHeader.FrameType) == 0x806) {
               if (memcmp(IPPacket->FrameHeader.SrcMAC, ARPFrame.FrameHeader.SrcMAC, 6) != 0) {
                   //接收到的 ARP 响应中的源 MAC 地址与发送 ARP 请求时设置的源 MAC 地址
                   // 不是一开始发送的广播 ARP 请求
                   printf(" MAC地址为:");
                   // 输出 MAC 地址
                   for (int i = 0; i < 6; i++) {
                       printf("%02x.", IPPacket->FrameHeader.SrcMAC[i]);
                   }
                   break;  // 找到 MAC 地址，退出
               }
           }
       }
    }
    
    return 0;
}