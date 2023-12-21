#pragma once
#include<iostream>
#include "pcap.h"
#include "winsock2.h"
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <cstring>
#include <string>
#include "stdio.h"
#pragma comment(lib,"ws2_32.lib")//��ʾ���ӵ�ʱ����ws2_32.lib
#pragma warning( disable : 4996 )//Ҫʹ�þɺ���
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define RT_TABLE_SIZE 256   //·�ɱ��С
using namespace std;
#pragma pack(1)//��1byte��ʽ����
//·�ɱ�ṹ
typedef struct router_table {
	ULONG netmask;         //��������
	ULONG desnet;          //Ŀ������
	ULONG nexthop;         //��һվ·��
}router_table;


typedef struct FrameHeader_t//֡�ײ�
{
	BYTE DesMac[6];
	BYTE SrcMac[6];
	WORD FrameType;
}FrameHeader_t;

typedef struct IPHeader_t {		//IP�ײ�
	BYTE	Ver_HLen;   //�汾��Э������
	BYTE	TOS;        //��������
	WORD	TotalLen;   //�ܳ���
	WORD	ID;         //��ʶ
	WORD	Flag_Segment; //��־��Ƭƫ��
	BYTE	TTL;        //��������
	BYTE	Protocol;   //Э��
	WORD	Checksum;   //У���
	ULONG	SrcIP;      //ԴIP��ַ
	ULONG	DstIP;      //Ŀ��IP��ַ
} IPHeader_t;

typedef struct IPData_t {	//����֡�ײ���IP�ײ������ݰ�
	FrameHeader_t	FrameHeader;
	IPHeader_t		IPHeader;
} IPData_t;

typedef struct ARPFrame_t//ARP֡
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
#pragma pack()//�ָ����뷽ʽ

//ѡ· ʵ���ƥ��
ULONG search(router_table* t, int tLength, ULONG DesIP)//������һ������IP
{
	ULONG best_desnet = 0;  //����ƥ���Ŀ������
	int best = -1;   //����ƥ��·�ɱ�����±�
	for (int i = 0; i < tLength; i++)
	{
		if ((t[i].netmask & DesIP) == t[i].desnet) //Ŀ��IP����������������Ŀ������Ƚ�
		{
			if (t[i].desnet >= best_desnet)//�ƥ��
			{
				best_desnet = t[i].desnet;  //��������ƥ���Ŀ������
				best = i;    //��������ƥ��·�ɱ�����±�
			}
		}
	}
	if (best == -1)
		return 0xffffffff;      //û��ƥ����
	else
		return t[best].nexthop;  //���ƥ����
}
//��·�ɱ�������û��������ʱ������Ż���
bool additem(router_table* t, int& tLength, router_table item)
{
	if (tLength == RT_TABLE_SIZE)  //·�ɱ����������
		return false;
	for (int i = 0; i < tLength; i++)
		if ((t[i].desnet == item.desnet) && (t[i].netmask == item.netmask) && (t[i].nexthop == item.nexthop))   //·�ɱ����Ѵ��ڸ���������
			return false;
	t[tLength] = item;   //��ӵ���β
	tLength = tLength + 1;
	return true;
}
//��·�ɱ���ɾ����
bool deleteitem(router_table* t, int& tLength, int index)
{
	if (tLength == 0)   //·�ɱ������ɾ��
		return false;
	for (int i = 0; i < tLength; i++)
		if (i == index)   //ɾ����index�����ı���
		{
			for (; i < tLength - 1; i++)
				t[i] = t[i + 1];
			tLength = tLength - 1;
			return true;
		}
	return false;   //·�ɱ��в����ڸ�������ɾ��
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

void printMAC(BYTE MAC[])//��ӡmac
{
	for (int i = 0; i < 5; i++)
		printf("%02X-", MAC[i]);
	printf("%02X\n", MAC[5]);
}
//��ӡ·�ɱ�
void print_rt(router_table* t, int& tLength)
{
	for (int i = 0; i < tLength; i++)
	{
		cout << "\t��������\t" << "Ŀ������\t" << "��һվ·��\t" << endl;
		cout <<"��" << i << "����  ";
		printIP(t[i].netmask);
		cout << "     ";
		printIP(t[i].desnet);
		cout << "     ";
		printIP(t[i].nexthop);
		cout << endl;
	}
}

void setchecksum(IPData_t* temp)//����У���
{
	temp->IPHeader.Checksum = 0;
	unsigned int sum = 0;
	WORD* t = (WORD*)&temp->IPHeader;//ÿ16λΪһ��
	for (int i = 0; i < sizeof(IPHeader_t) / 2; i++)
	{
		sum += t[i];
		while (sum >= 0x10000)//������������лؾ�
		{
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}
	temp->IPHeader.Checksum = ~sum;//���ȡ��
}

bool checkchecksum(IPData_t* temp)//����
{
	unsigned int sum = 0;
	WORD* t = (WORD*)&temp->IPHeader;
	for (int i = 0; i < sizeof(IPHeader_t) / 2; i++)
	{
		sum += t[i];
		while (sum >= 0x10000)//����ԭ��У���һ��������
		{
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}
	if (sum == 65535)//Դ��+����-��ȫ1
		return 1;//У�����ȷ
	return 0;
}
int main()
{
	int number = 0;
	bool flag = 0;//��־λ����ʾ�Ƿ�õ�IPv4����0Ϊû�еõ���
	BYTE my_mac[6];
	BYTE its_mac[6];
	ULONG my_ip;
	NextMac nextMac[2];
	nextMac[0].is_null = false;
	nextMac[1].is_null = false;

	router_table* rt = new router_table[RT_TABLE_SIZE];//��·�ɱ���������������
	int rt_length = 0;//·�ɱ�ĳ�ʼ����

	pcap_if_t* alldevs;
	pcap_if_t* d;
	pcap_addr_t* a;

	ULONG targetIP;

	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
		cerr << "��������ʱ����: " << errbuf << endl;
		return 1;
	}
	int count = 0;
	d = alldevs;
	while (d != NULL) {
		count++;
		cout << "����" << count << "�� " << d->name << endl;
		cout << "   ������ϢΪ��" << d->description << endl;
		for (pcap_addr* a = d->addresses; a != nullptr; a = a->next)//�ж��Ƿ�������ӿڵĵ�ַ��Ϣ
		{
			if (((struct sockaddr_in*)a->addr)->sin_family == AF_INET && a->addr)
			{//��ӡip��ַ
				std::cout << "   IP��ַΪ��" << inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr) << endl;
				std::cout << "   ��������Ϊ��" << inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr) << endl;

			}
			
		}
		std::cout << endl;
		d = d->next;
	}

	int selected_device;
	std::cout << "ѡ��һ�������豸��1-" << count << "��: ";
	cin >> selected_device;

	pcap_if_t* device = alldevs;
	for (int i = 1; i < selected_device; i++) {
		device = device->next;
	}

	pcap_t* handle = pcap_open(device->name, 1024, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
	if (handle == NULL) {
		cerr << "���豸ʱ����: " << errbuf << endl;
		pcap_freealldevs(alldevs);
		return 1;
	}
	cout << "������Ӧ����Ϣ���£�" << endl;
	//��ӡѡ��������IP���������롢�㲥��ַ
	for (a = device->addresses; a != NULL; a = a->next)
	{
		if (a->addr->sa_family == AF_INET)
		{
			std::cout << "   IP��ַΪ��" << inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr) << endl;
			std::cout << "   ��������Ϊ��" << inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr) << endl;
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
			additem(rt, rt_length, temp);//������Ϣ��ΪĬ��·��
		}
	}



	char errbuf1[PCAP_ERRBUF_SIZE];
	pcap_t* p;//��¼����pcap_open()�ķ���ֵ���������

	p = pcap_open(device->name, 1500, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf1);//������ӿ�

	u_int net_mask;
	net_mask = ((sockaddr_in*)(device->addresses->netmask))->sin_addr.S_un.S_addr;
	bpf_program fcode;
	char packet_filter[] = "ip or arp";
	if (pcap_compile(handle, &fcode, packet_filter, 1, net_mask) < 0) {
		std::cout << "�޷��������ݰ�������" << endl;
		pcap_freealldevs(alldevs);
		return 1;
	}
	if (pcap_setfilter(handle, &fcode) < 0) {
		std::cout << "���������ô���" << endl;
		pcap_freealldevs(alldevs);
		return 1;
	}

//���Լ�����arp������ȡ������MAC
	int i;
	BYTE scrMAC[6];
	ULONG scrIP;
	for (i = 0; i < 6; i++)
	{
		scrMAC[i] = 0x66;
	}
	scrIP = inet_addr("112.112.112.112");//����IP

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
	cout << "��ȡ��������Mac��ַ" << endl;


	//�ػ��Լ���MAC
	pcap_pkthdr* pkt_header1 = new pcap_pkthdr[1500];
	const u_char* pkt_data1;
	int res;
	ARPFrame_t* ARPFrame1;

entry:
	//���ӻ�ɾ��·�ɱ���

	ULONG NetMask, DesNet, NextHop;
	char* netmask = new char[20];
	char* desnet = new char[20];
	char* nexthop = new char[20];
	bool stop = 1;//stop=0ʱ��ֹͣ�޸�·�ɱ�
	int sent_time = 0;
	cout << "�Ƿ�Ҫ�޸�·�ɱ�(y/n):" << endl;
	char ch1;
	cin >> ch1;
	if (ch1 == 'n')
	{
		stop = 0;
		cout << "·�ɱ����£�" << endl;
		print_rt(rt, rt_length);
	}
	while (stop)
	{
		cout << "��Ҫִ�еĹ��ܣ����·�ɱ��0������ɾ��·�ɱ��1��" << endl;
		string str;
		cin >> str;

		if (str == "0")
		{
			cout << "��ӵ�·�ɱ���Ϊ:" << endl;
			cout << "    Ŀ�����磺";
			cin >> desnet;
			cout << "    �������룺";
			cin >> netmask;
			cout << "   ��һ����ַ��";
			cin >> nexthop;
			DesNet = inet_addr(desnet);
			NetMask = inet_addr(netmask);
			NextHop = inet_addr(nexthop);

			router_table temp;
			temp.netmask = NetMask;
			temp.desnet = DesNet;
			temp.nexthop = NextHop;

			additem(rt, rt_length, temp);

			cout << "�޸ĺ��·�ɱ����£�" << endl;
			print_rt(rt, rt_length);//��ӡ·�ɱ�

			char ch;
			cout << "�Ƿ�Ҫִ�в�������y/n��" << endl;

			cin >> ch;
			if (ch == 'n')
			{
				stop = 0;
				cout << "���յ�·�ɱ�����:" << endl;
				print_rt(rt, rt_length);
				break;
			}

		}
		else if (str == "1")
		{
			int index;
			cout << "������Ҫɾ���ı������������㿪ʼ��" << endl;
			cin >> index;//���±�0��ʼ
			deleteitem(rt, rt_length, index);

			cout << "�޸ĺ��·�ɱ����£�" << endl;
			print_rt(rt, rt_length);//��ӡ·�ɱ�

			char ch;
			cout << "�Ƿ�Ҫִ�в�������y/n��" << endl;
			cin >> ch;
			if (ch == 'n')
			{
				stop = 0;
				cout << "���յ�·�ɱ�����:" << endl;
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
				cout << "����IP:";
				printIP(ARPFrame1->SendIP);
				cout << endl;

				cout << "����MAC:";
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

	//��ȡĿ��macΪ����mac��Ŀ��ip�Ǳ���ip��ip���ݱ�

	ULONG nextIP;//·�ɵ���һվ
	flag = 0;

	IPData_t* IPPacket;


	pcap_pkthdr* pkt_header = new pcap_pkthdr[1500];
	const u_char* pkt_data;
	while (1)
	{
		//���ݰ��Ļ�ȡ
		int ret_pcap_next_ex;
		ret_pcap_next_ex = pcap_next_ex(handle, &pkt_header, &pkt_data);//�ڴ򿪵�����ӿڿ��ϻ�ȡ�������ݰ�
		if (ret_pcap_next_ex)
		{
			WORD RecvChecksum;
			WORD FrameType;

			IPPacket = (IPData_t*)pkt_data;

			ULONG Len = pkt_header->len + sizeof(FrameHeader_t);//���ݰ���С����֡���ݲ��ֳ��Ⱥ�֡�ײ�����
			u_char* sendAllPacket = new u_char[Len];
			for (i = 0; i < Len; i++)
			{
				sendAllPacket[i] = pkt_data[i];
			}

			RecvChecksum = IPPacket->IPHeader.Checksum;
			IPPacket->IPHeader.Checksum = 0;
			FrameType = IPPacket->FrameHeader.FrameType;
			bool desmac_equal = 1;//Ŀ��mac��ַ�뱾��mac��ַ�Ƿ���ͬ����ͬΪ1��
			for (int i = 0; i < 6; i++)
			{
				if (my_mac[i] != IPPacket->FrameHeader.DesMac[i])
				{
					desmac_equal = 0;
				}
			}
			bool desIP_equal = 0;//Ŀ��IP�뱾��IP�Ƿ���ͬ������ͬΪ1��
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

			if (Is_ipv4 && desmac_equal && desIP_equal)//����Ŀ��IP���Ǳ���IP��Ŀ��MACΪ����MAC��IPv4�� 
			{
				cout << "\nIP���ݰ����Ľ������£�" << endl;
				cout << "���ݰ���Ϣ���£�" << endl;
				cout << "  IP�汾: IPv" << ((IPPacket->IPHeader.Ver_HLen & 0xf0) >> 4) << endl;
				cout << "  IPЭ���ײ�����: " << (IPPacket->IPHeader.Ver_HLen & 0x0f) << endl;
				cout << "  ��������: " << dec << IPPacket->IPHeader.TOS << endl;
				cout << "  ���ݰ��ܳ���: " << dec << ntohs(IPPacket->IPHeader.TotalLen) << endl;
				cout << "  ��ʶ: " << "0x" << ntohs(IPPacket->IPHeader.ID) << endl;
				cout << "  ����ʱ��: " << dec << IPPacket->IPHeader.TTL << endl;
				cout << "  Э��: " << dec << IPPacket->IPHeader.Protocol << endl;
				cout << "  ԴIP��ַ: ";
				printIP(IPPacket->IPHeader.SrcIP);
				cout << endl;
				cout << "  Ŀ��IP: ";
				printIP(IPPacket->IPHeader.DstIP);
				cout << endl;

				nextIP = search(rt, rt_length, IPPacket->IPHeader.DstIP);
				cout << "  ·�ɱ���Ϊ��" << rt_length << endl;
				
				if (nextIP == 0)
				{
					nextIP = IPPacket->IPHeader.DstIP;
				}
				else if (nextIP == 0xffffffff)
				{
					cout << "·�ɱ��ڲ��ɴ�޷�ת�����ݰ��������ԡ�" << endl;
					sent_time = 8;
				}

				cout << "  ��һ����ַΪ:";
				printIP(nextIP);
				cout << endl;

				flag = 1;

				if (sent_time == 8)
					break;

				if (!nextMac[sent_time % 2].is_null) {
					//��nextIP��arp����ȡMAC��ַ
					nextMac[sent_time % 2].NextIP = nextIP;

					cout << "ARP��ȡ��һ����MAC��ַ:" << endl;
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
								cout << "  ��һ����MAC��ַΪ:";
								for (int i = 0; i < 6; i++)
								{
									nextMac[sent_time % 2].NextMAC[i] = ARPFrame2->FrameHeader.SrcMac[i];
									cout << hex << (int)nextMac[sent_time % 2].NextMAC[i];
									if (i != 5)cout << "-";
									else cout << endl;
								}
								flag1 = 1;
								cout << "  ��һ����IP��ַΪ:";
								printIP(ARPFrame2->SendIP);
								cout << endl;
							}
						}

					}
					nextMac[sent_time % 2].is_null = true;
					cout << "  ARP������е�ӳ���ϵΪ��";
					printIP(nextMac[sent_time % 2].NextIP);
					cout << " <----> ";
					printMAC(nextMac[sent_time % 2].NextMAC);
					cout << "===================================" << endl;
				}
				for (int i = 0; i < 6; i++) {
					its_mac[i] = nextMac[sent_time % 2].NextMAC[i];
				}
				//ת����
				cout << "���ݰ�ת�������ԣ�" << endl;
				IPData_t* TempIP;
				TempIP = (IPData_t*)sendAllPacket;
				for (int t = 0; t < 6; t++)
				{
					TempIP->FrameHeader.DesMac[t] = its_mac[t];//Ŀ��mac��ַ��Ϊ��һ������ip��ַ��Ӧ��mac��ַ���������䡣
					TempIP->FrameHeader.SrcMac[t] = my_mac[t];
				}
				if (!pcap_sendpacket(handle, sendAllPacket, Len))
				{
					IPData_t* t;
					t = (IPData_t*)sendAllPacket;
					cout << "  ԴIP��ַ��";
					printIP(t->IPHeader.SrcIP);
					cout << "\t";

					cout << "  Ŀ��IP��ַ��";
					printIP(t->IPHeader.DstIP);
					cout << endl;

					cout << "  Ŀ��MAC��ַ��";
					for (int i = 0; i < 6; i++)
					{
						cout << hex << (int)t->FrameHeader.DesMac[i];
						if (i != 5)cout << "-";
					}
					cout << "\t";
					cout << "  ԴMAC��ַ��";
					for (i = 0; i < 6; i++)
					{
						cout << hex << (int)t->FrameHeader.SrcMac[i];
						if (i != 5)cout << "-";
					}
					cout << endl;
				}

				sent_time++;
				cout << "======��" << sent_time << "��ת��=======" << endl;
				if (sent_time == 8)
					break;
			}
			
		}

	}

	if (sent_time == 8)
		goto entry;
	pcap_freealldevs(alldevs);//�ͷ��豸�б�
	return 0;

}
