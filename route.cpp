#pragma once
#include<iostream>
#include "pcap.h"
#include "winsock2.h"
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <cstring>
#include <string>
#include "stdio.h"
#pragma comment(lib,"ws2_32.lib")//表示链接的时侯找ws2_32.lib
#pragma warning( disable : 4996 )//要使用旧函数
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define RT_TABLE_SIZE 256   //路由表大小
using namespace std;
#pragma pack(1)//以1byte方式对齐
//路由表结构
typedef struct router_table {
	ULONG netmask;         //网络掩码
	ULONG desnet;          //目的网络
	ULONG nexthop;         //下一站路由
}router_table;


typedef struct FrameHeader_t//帧首部
{
	BYTE DesMac[6];
	BYTE SrcMac[6];
	WORD FrameType;
}FrameHeader_t;

typedef struct IPHeader_t {		//IP首部
	BYTE	Ver_HLen;   //版本与协议类型
	BYTE	TOS;        //服务类型
	WORD	TotalLen;   //总长度
	WORD	ID;         //标识
	WORD	Flag_Segment; //标志和片偏移
	BYTE	TTL;        //生存周期
	BYTE	Protocol;   //协议
	WORD	Checksum;   //校验和
	ULONG	SrcIP;      //源IP地址
	ULONG	DstIP;      //目的IP地址
} IPHeader_t;

typedef struct IPData_t {	//包含帧首部和IP首部的数据包
	FrameHeader_t	FrameHeader;
	IPHeader_t		IPHeader;
} IPData_t;

typedef struct ARPFrame_t//ARP帧
{
	FrameHeader_t FrameHeader;
	WORD HardwareType;
	WORD ProtocolType;
	BYTE HLen;
	BYTE PLen;
	WORD Operation;
	BYTE SendHa[6];
	DWORD SendIP;
	BYTE RecvHa[6];
	DWORD RecvIP;
}ARPFrame_t;

typedef struct NextMac {
	ULONG NextIP;
	BYTE NextMAC[6];
	bool is_null;
} NextMac;
#pragma pack()//恢复对齐方式

//选路 实现最长匹配
ULONG search(router_table* t, int tLength, ULONG DesIP)//返回下一跳步的IP
{
	ULONG best_desnet = 0;  //最优匹配的目的网络
	int best = -1;   //最优匹配路由表项的下标
	for (int i = 0; i < tLength; i++)
	{
		if ((t[i].netmask & DesIP) == t[i].desnet) //目的IP和网络掩码相与后和目的网络比较
		{
			if (t[i].desnet >= best_desnet)//最长匹配
			{
				best_desnet = t[i].desnet;  //保存最优匹配的目的网络
				best = i;    //保存最优匹配路由表项的下标
			}
		}
	}
	if (best == -1)
		return 0xffffffff;      //没有匹配项
	else
		return t[best].nexthop;  //获得匹配项
}
//向路由表中添加项（没有做插入时排序的优化）
bool additem(router_table* t, int& tLength, router_table item)
{
	if (tLength == RT_TABLE_SIZE)  //路由表满则不能添加
		return false;
	for (int i = 0; i < tLength; i++)
		if ((t[i].desnet == item.desnet) && (t[i].netmask == item.netmask) && (t[i].nexthop == item.nexthop))   //路由表中已存在该项，则不能添加
			return false;
	t[tLength] = item;   //添加到表尾
	tLength = tLength + 1;
	return true;
}
//从路由表中删除项
bool deleteitem(router_table* t, int& tLength, int index)
{
	if (tLength == 0)   //路由表空则不能删除
		return false;
	for (int i = 0; i < tLength; i++)
		if (i == index)   //删除以index索引的表项
		{
			for (; i < tLength - 1; i++)
				t[i] = t[i + 1];
			tLength = tLength - 1;
			return true;
		}
	return false;   //路由表中不存在该项则不能删除
}

void printIP(ULONG IP)
{
	BYTE* p = (BYTE*)&IP;
	for (int i = 0; i < 3; i++)
	{
		cout << dec << (int)*p << ".";
		p++;
	}
	cout << dec << (int)*p << " ";
}

void printMAC(BYTE MAC[])//打印mac
{
	for (int i = 0; i < 5; i++)
		printf("%02X-", MAC[i]);
	printf("%02X\n", MAC[5]);
}
//打印路由表
void print_rt(router_table* t, int& tLength)
{
	for (int i = 0; i < tLength; i++)
	{
		cout << "\t网络掩码\t" << "目的网络\t" << "下一站路由\t" << endl;
		cout <<"第" << i << "条：  ";
		printIP(t[i].netmask);
		cout << "     ";
		printIP(t[i].desnet);
		cout << "     ";
		printIP(t[i].nexthop);
		cout << endl;
	}
}

void setchecksum(IPData_t* temp)//设置校验和
{
	temp->IPHeader.Checksum = 0;
	unsigned int sum = 0;
	WORD* t = (WORD*)&temp->IPHeader;//每16位为一组
	for (int i = 0; i < sizeof(IPHeader_t) / 2; i++)
	{
		sum += t[i];
		while (sum >= 0x10000)//如果溢出，则进行回卷
		{
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}
	temp->IPHeader.Checksum = ~sum;//结果取反
}

bool checkchecksum(IPData_t* temp)//检验
{
	unsigned int sum = 0;
	WORD* t = (WORD*)&temp->IPHeader;
	for (int i = 0; i < sizeof(IPHeader_t) / 2; i++)
	{
		sum += t[i];
		while (sum >= 0x10000)//包含原有校验和一起进行相加
		{
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}
	if (sum == 65535)//源码+反码-》全1
		return 1;//校验和正确
	return 0;
}
int main()
{
	int number = 0;
	bool flag = 0;//标志位，表示是否得到IPv4包，0为没有得到。
	BYTE my_mac[6];
	BYTE its_mac[6];
	ULONG my_ip;
	NextMac nextMac[2];
	nextMac[0].is_null = false;
	nextMac[1].is_null = false;

	router_table* rt = new router_table[RT_TABLE_SIZE];//把路由表项用链表串联起来
	int rt_length = 0;//路由表的初始长度

	pcap_if_t* alldevs;
	pcap_if_t* d;
	pcap_addr_t* a;

	ULONG targetIP;

	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
		cerr << "查找网卡时出错: " << errbuf << endl;
		return 1;
	}
	int count = 0;
	d = alldevs;
	while (d != NULL) {
		count++;
		cout << "网卡" << count << "： " << d->name << endl;
		cout << "   描述信息为：" << d->description << endl;
		for (pcap_addr* a = d->addresses; a != nullptr; a = a->next)//判断是否有网络接口的地址信息
		{
			if (((struct sockaddr_in*)a->addr)->sin_family == AF_INET && a->addr)
			{//打印ip地址
				std::cout << "   IP地址为：" << inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr) << endl;
				std::cout << "   子网掩码为：" << inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr) << endl;

			}
			
		}
		std::cout << endl;
		d = d->next;
	}

	int selected_device;
	std::cout << "选择一个网卡设备（1-" << count << "）: ";
	cin >> selected_device;

	pcap_if_t* device = alldevs;
	for (int i = 1; i < selected_device; i++) {
		device = device->next;
	}

	pcap_t* handle = pcap_open(device->name, 1024, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
	if (handle == NULL) {
		cerr << "打开设备时出错: " << errbuf << endl;
		pcap_freealldevs(alldevs);
		return 1;
	}
	cout << "网卡对应的信息如下：" << endl;
	//打印选择网卡的IP、子网掩码、广播地址
	for (a = device->addresses; a != NULL; a = a->next)
	{
		if (a->addr->sa_family == AF_INET)
		{
			std::cout << "   IP地址为：" << inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr) << endl;
			std::cout << "   子网掩码为：" << inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr) << endl;
			cout << endl;

			ULONG NetMask, DesNet, NextHop;
			DesNet = (((sockaddr_in*)a->addr)->sin_addr).s_addr;
			NetMask = (((sockaddr_in*)a->netmask)->sin_addr).s_addr;
			DesNet = DesNet & NetMask;
			NextHop = 0;
			router_table temp;
			temp.netmask = NetMask;
			temp.desnet = DesNet;
			temp.nexthop = NextHop;
			additem(rt, rt_length, temp);//本机信息作为默认路由
		}
	}



	char errbuf1[PCAP_ERRBUF_SIZE];
	pcap_t* p;//记录调用pcap_open()的返回值，即句柄。

	p = pcap_open(device->name, 1500, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf1);//打开网络接口

	u_int net_mask;
	net_mask = ((sockaddr_in*)(device->addresses->netmask))->sin_addr.S_un.S_addr;
	bpf_program fcode;
	char packet_filter[] = "ip or arp";
	if (pcap_compile(handle, &fcode, packet_filter, 1, net_mask) < 0) {
		std::cout << "无法编译数据包过滤器" << endl;
		pcap_freealldevs(alldevs);
		return 1;
	}
	if (pcap_setfilter(handle, &fcode) < 0) {
		std::cout << "过滤器设置错误" << endl;
		pcap_freealldevs(alldevs);
		return 1;
	}

//向自己发送arp包，获取本机的MAC
	int i;
	BYTE scrMAC[6];
	ULONG scrIP;
	for (i = 0; i < 6; i++)
	{
		scrMAC[i] = 0x66;
	}
	scrIP = inet_addr("112.112.112.112");//虚拟IP

	for (a = device->addresses; a != NULL; a = a->next)
	{
		if (a->addr->sa_family == AF_INET)
		{
			targetIP = inet_addr(inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr));
			my_ip = targetIP;
		}
	}
	ARPFrame_t ARPFrame;
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.DesMac[i] = 0xff;
		ARPFrame.FrameHeader.SrcMac[i] = scrMAC[i];
		ARPFrame.SendHa[i] = scrMAC[i];
		ARPFrame.RecvHa[i] = 0;
	}

	ARPFrame.FrameHeader.FrameType = htons(0x0806);
	ARPFrame.HardwareType = htons(0x0001);
	ARPFrame.ProtocolType = htons(0x0800);
	ARPFrame.HLen = 6;
	ARPFrame.PLen = 4;
	ARPFrame.Operation = htons(0x0001);
	ARPFrame.SendIP = scrIP;
	ARPFrame.RecvIP = targetIP;
	int ret_send = pcap_sendpacket(handle, (u_char*)&ARPFrame, sizeof(ARPFrame_t));
	cout << "获取绑定网卡的Mac地址" << endl;


	//截获自己的MAC
	pcap_pkthdr* pkt_header1 = new pcap_pkthdr[1500];
	const u_char* pkt_data1;
	int res;
	ARPFrame_t* ARPFrame1;

entry:
	//增加或删除路由表项

	ULONG NetMask, DesNet, NextHop;
	char* netmask = new char[20];
	char* desnet = new char[20];
	char* nexthop = new char[20];
	bool stop = 1;//stop=0时，停止修改路由表
	int sent_time = 0;
	cout << "是否要修改路由表(y/n):" << endl;
	char ch1;
	cin >> ch1;
	if (ch1 == 'n')
	{
		stop = 0;
		cout << "路由表如下：" << endl;
		print_rt(rt, rt_length);
	}
	while (stop)
	{
		cout << "将要执行的功能：添加路由表项（0）或者删除路由表项（1）" << endl;
		string str;
		cin >> str;

		if (str == "0")
		{
			cout << "添加的路由表项为:" << endl;
			cout << "    目的网络：";
			cin >> desnet;
			cout << "    网络掩码：";
			cin >> netmask;
			cout << "   下一跳地址：";
			cin >> nexthop;
			DesNet = inet_addr(desnet);
			NetMask = inet_addr(netmask);
			NextHop = inet_addr(nexthop);

			router_table temp;
			temp.netmask = NetMask;
			temp.desnet = DesNet;
			temp.nexthop = NextHop;

			additem(rt, rt_length, temp);

			cout << "修改后的路由表如下：" << endl;
			print_rt(rt, rt_length);//打印路由表

			char ch;
			cout << "是否还要执行操作：（y/n）" << endl;

			cin >> ch;
			if (ch == 'n')
			{
				stop = 0;
				cout << "最终的路由表如下:" << endl;
				print_rt(rt, rt_length);
				break;
			}

		}
		else if (str == "1")
		{
			int index;
			cout << "请输入要删除的表项索引（从零开始）" << endl;
			cin >> index;//从下标0开始
			deleteitem(rt, rt_length, index);

			cout << "修改后的路由表如下：" << endl;
			print_rt(rt, rt_length);//打印路由表

			char ch;
			cout << "是否还要执行操作：（y/n）" << endl;
			cin >> ch;
			if (ch == 'n')
			{
				stop = 0;
				cout << "最终的路由表如下:" << endl;
				print_rt(rt, rt_length);
				break;
			}

		}

	}


	while (!flag)
	{
		res = pcap_next_ex(handle, &pkt_header1, &pkt_data1);
		if ((res == 0))
		{
			continue;
		}
		if (res == 1)
		{
			ARPFrame1 = (ARPFrame_t*)pkt_data1;
			if (ARPFrame1->SendIP == targetIP && ARPFrame1->RecvIP == scrIP)
			{
				cout << "本机IP:";
				printIP(ARPFrame1->SendIP);
				cout << endl;

				cout << "本机MAC:";
				for (int i = 0; i < 6; i++)
				{
					my_mac[i] = ARPFrame1->SendHa[i];
					cout << hex << (int)my_mac[i];
					if (i != 5)cout << "-";
					else cout << endl;
				}
				flag = 1;

			}

		}

	}

	//获取目的mac为本机mac，目的ip非本机ip的ip数据报

	ULONG nextIP;//路由的下一站
	flag = 0;

	IPData_t* IPPacket;


	pcap_pkthdr* pkt_header = new pcap_pkthdr[1500];
	const u_char* pkt_data;
	while (1)
	{
		//数据包的获取
		int ret_pcap_next_ex;
		ret_pcap_next_ex = pcap_next_ex(handle, &pkt_header, &pkt_data);//在打开的网络接口卡上获取网络数据包
		if (ret_pcap_next_ex)
		{
			WORD RecvChecksum;
			WORD FrameType;

			IPPacket = (IPData_t*)pkt_data;

			ULONG Len = pkt_header->len + sizeof(FrameHeader_t);//数据包大小包括帧数据部分长度和帧首部长度
			u_char* sendAllPacket = new u_char[Len];
			for (i = 0; i < Len; i++)
			{
				sendAllPacket[i] = pkt_data[i];
			}

			RecvChecksum = IPPacket->IPHeader.Checksum;
			IPPacket->IPHeader.Checksum = 0;
			FrameType = IPPacket->FrameHeader.FrameType;
			bool desmac_equal = 1;//目的mac地址与本机mac地址是否相同，相同为1；
			for (int i = 0; i < 6; i++)
			{
				if (my_mac[i] != IPPacket->FrameHeader.DesMac[i])
				{
					desmac_equal = 0;
				}
			}
			bool desIP_equal = 0;//目的IP与本机IP是否相同，不相同为1；
			if (IPPacket->IPHeader.DstIP != my_ip)
			{
				desIP_equal = 1;
				targetIP = IPPacket->IPHeader.DstIP;
			}
			bool Is_ipv4 = 0;
			if (FrameType == 0x0008)
			{
				Is_ipv4 = 1;
			}

			if (Is_ipv4 && desmac_equal && desIP_equal)//处理目的IP不是本机IP，目的MAC为本机MAC的IPv4包 
			{
				cout << "\nIP数据包报文解析如下：" << endl;
				cout << "数据包信息如下：" << endl;
				cout << "  IP版本: IPv" << ((IPPacket->IPHeader.Ver_HLen & 0xf0) >> 4) << endl;
				cout << "  IP协议首部长度: " << (IPPacket->IPHeader.Ver_HLen & 0x0f) << endl;
				cout << "  服务类型: " << dec << IPPacket->IPHeader.TOS << endl;
				cout << "  数据包总长度: " << dec << ntohs(IPPacket->IPHeader.TotalLen) << endl;
				cout << "  标识: " << "0x" << ntohs(IPPacket->IPHeader.ID) << endl;
				cout << "  生存时间: " << dec << IPPacket->IPHeader.TTL << endl;
				cout << "  协议: " << dec << IPPacket->IPHeader.Protocol << endl;
				cout << "  源IP地址: ";
				printIP(IPPacket->IPHeader.SrcIP);
				cout << endl;
				cout << "  目的IP: ";
				printIP(IPPacket->IPHeader.DstIP);
				cout << endl;

				nextIP = search(rt, rt_length, IPPacket->IPHeader.DstIP);
				cout << "  路由表长度为：" << rt_length << endl;
				
				if (nextIP == 0)
				{
					nextIP = IPPacket->IPHeader.DstIP;
				}
				else if (nextIP == 0xffffffff)
				{
					cout << "路由表内不可达。无法转发数据包，请重试。" << endl;
					sent_time = 8;
				}

				cout << "  下一跳地址为:";
				printIP(nextIP);
				cout << endl;

				flag = 1;

				if (sent_time == 8)
					break;

				if (!nextMac[sent_time % 2].is_null) {
					//向nextIP发arp包获取MAC地址
					nextMac[sent_time % 2].NextIP = nextIP;

					cout << "ARP获取下一跳的MAC地址:" << endl;
					for (i = 0; i < 6; i++)
					{
						scrMAC[i] = my_mac[i];
					}
					scrIP = my_ip;


					targetIP = nextIP;

					for (int i = 0; i < 6; i++)
					{
						ARPFrame.FrameHeader.DesMac[i] = 0xff;
						ARPFrame.FrameHeader.SrcMac[i] = scrMAC[i];
						ARPFrame.SendHa[i] = scrMAC[i];
						ARPFrame.RecvHa[i] = 0;
					}

					ARPFrame.FrameHeader.FrameType = htons(0x0806);
					ARPFrame.HardwareType = htons(0x0001);
					ARPFrame.ProtocolType = htons(0x0800);
					ARPFrame.HLen = 6;
					ARPFrame.PLen = 4;
					ARPFrame.Operation = htons(0x0001);
					//ARPFrame.SendIP = my_ip;
					ARPFrame.SendIP = scrIP;
					cout << "  sendIP:";
					printIP(ARPFrame.SendIP);
					cout << endl;
					//ARPFrame.RecvIP = nextIP;
					ARPFrame.RecvIP = targetIP;
					cout << "  recvIP:";
					printIP(ARPFrame.RecvIP);
					cout << endl;
					int send_ret = pcap_sendpacket(handle, (u_char*)&ARPFrame, sizeof(ARPFrame_t));

					pcap_pkthdr* pkt_header2 = new pcap_pkthdr[1500];
					const u_char* pkt_data2;

					int res;
					ARPFrame_t* ARPFrame2;

					int flag1 = 0;
					while (!flag1)
					{
						res = pcap_next_ex(handle, &pkt_header2, &pkt_data2);

						if ((res == 0))
						{
							continue;
						}
						if (res == 1)
						{
							ARPFrame2 = (ARPFrame_t*)pkt_data2;

							if (ARPFrame2->SendIP == nextIP && ARPFrame2->RecvIP == my_ip)
							{
								cout << "  下一跳的MAC地址为:";
								for (int i = 0; i < 6; i++)
								{
									nextMac[sent_time % 2].NextMAC[i] = ARPFrame2->FrameHeader.SrcMac[i];
									cout << hex << (int)nextMac[sent_time % 2].NextMAC[i];
									if (i != 5)cout << "-";
									else cout << endl;
								}
								flag1 = 1;
								cout << "  下一跳的IP地址为:";
								printIP(ARPFrame2->SendIP);
								cout << endl;
							}
						}

					}
					nextMac[sent_time % 2].is_null = true;
					cout << "  ARP缓存表中的映射关系为：";
					printIP(nextMac[sent_time % 2].NextIP);
					cout << " <----> ";
					printMAC(nextMac[sent_time % 2].NextMAC);
					cout << "===================================" << endl;
				}
				for (int i = 0; i < 6; i++) {
					its_mac[i] = nextMac[sent_time % 2].NextMAC[i];
				}
				//转发包
				cout << "数据包转发后属性：" << endl;
				IPData_t* TempIP;
				TempIP = (IPData_t*)sendAllPacket;
				for (int t = 0; t < 6; t++)
				{
					TempIP->FrameHeader.DesMac[t] = its_mac[t];//目的mac地址换为下一跳步的ip地址对应的mac地址，其他不变。
					TempIP->FrameHeader.SrcMac[t] = my_mac[t];
				}
				if (!pcap_sendpacket(handle, sendAllPacket, Len))
				{
					IPData_t* t;
					t = (IPData_t*)sendAllPacket;
					cout << "  源IP地址：";
					printIP(t->IPHeader.SrcIP);
					cout << "\t";

					cout << "  目的IP地址：";
					printIP(t->IPHeader.DstIP);
					cout << endl;

					cout << "  目的MAC地址：";
					for (int i = 0; i < 6; i++)
					{
						cout << hex << (int)t->FrameHeader.DesMac[i];
						if (i != 5)cout << "-";
					}
					cout << "\t";
					cout << "  源MAC地址：";
					for (i = 0; i < 6; i++)
					{
						cout << hex << (int)t->FrameHeader.SrcMac[i];
						if (i != 5)cout << "-";
					}
					cout << endl;
				}

				sent_time++;
				cout << "======第" << sent_time << "次转发=======" << endl;
				if (sent_time == 8)
					break;
			}
			
		}

	}

	if (sent_time == 8)
		goto entry;
	pcap_freealldevs(alldevs);//释放设备列表
	return 0;

}
