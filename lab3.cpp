#include <iostream>
#include "pcap.h"
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <vector>
#include <cstring>
#include <string>

using namespace std;
//���ĸ�ʽ
#pragma pack(1)//��1byte��ʽ����

typedef struct FrameHeader_t {//֡�ײ�
    BYTE DesMAC[6];//Ŀ�ĵ�ַ
    BYTE SrcMAC[6];//Դ��ַ
    WORD FrameType;//֡����
}FrameHeader_t;

typedef struct ARPFrame_t {//IP�ײ�
    FrameHeader_t FrameHeader;
    WORD HardwareType;//Ӳ������
    WORD ProtocolType;//Э������
    BYTE HLen;//Ӳ����ַ����
    BYTE PLen;//Э���ַ����
    WORD Operation;//��������
    BYTE SendHa[6];//���ͷ�MAC��ַ
    DWORD SendIP;//���ͷ�IP��ַ
    BYTE RecvHa[6];//���շ�MAC��ַ
    DWORD RecvIP;//���շ�IP��ַ
}ARPFrame_t;

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    vector<string> ip;
    // ��ȡ���������豸�б�
    pcap_if_t* alldevs;
    pcap_if_t* d;

    ARPFrame_t ARPFrame;
    ARPFrame_t* IPPacket;
    pcap_pkthdr* pkt_header;
    const u_char* pkt_data;
    pcap_addr_t* a;

    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
        cerr << "��������ʱ����: " << errbuf << endl;
        return 1;
    }
    int count = 0;
    d = alldevs;
    while (d != NULL) {
        count++;
        cout << "����" << count << "�� " << d ->name << endl;
        cout << "   ������ϢΪ��" << d ->description << endl;
        for (pcap_addr* a = d->addresses; a != nullptr; a = a->next)//�ж��Ƿ�������ӿڵĵ�ַ��Ϣ
        {
            if (((struct sockaddr_in*)a->addr)->sin_family == AF_INET && a->addr)
            {//��ӡip��ַ
                std::cout << "   IP��ַΪ��" << inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr) << endl;
                std::cout << "   ��������Ϊ��" << inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr) << endl;

                //��ip�б�������飬�������ѡ��Ŀ��ip����װ���ݰ�
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
    std::cout << "ѡ��һ�������豸��1-" << count << "��: ";
    cin >> selected_device;

    pcap_if_t*  device = alldevs;
    for (int i = 1; i < selected_device; i++) {
        device = device->next;
    }

    pcap_t* handle = pcap_open(device->name, 1024, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
    if (handle == NULL) {
        cerr << "���豸ʱ����: " << errbuf << endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

    u_int netmask;
    netmask = ((sockaddr_in*)(device->addresses->netmask))->sin_addr.S_un.S_addr;
    bpf_program fcode;
    char packet_filter[] = "ether proto \\arp";
    if (pcap_compile( handle, &fcode, packet_filter, 1, netmask) < 0) {
        std::cout << "�޷��������ݰ�������" << endl;
        pcap_freealldevs(alldevs);
        return 1;
    }
    if (pcap_setfilter(handle, &fcode) < 0) {
        std::cout << "���������ô���" << endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

   

    std::cout << "������Ҫ�����IP��ַ��";
    char addr[15];
    cin >> addr;

    //����Ŀ��MAC��ַΪ�㲥��ַ
    for (int i = 0; i < 6; i++)
        ARPFrame.FrameHeader.DesMAC[i] = 0xFF;//��ʾ�㲥

    //����ԴMAC��ַΪ����������MAC��ַ
    for (int i = 0; i < 6; i++)
        ARPFrame.FrameHeader.SrcMAC[i] = 0x66;

    //�����շ���Ӳ����ַ��RecvHa������Ϊ0����ʾĿ�ĵ�ַδ֪
    for (int i = 0; i < 6; i++)
        ARPFrame.RecvHa[i] = 0;//��ʾĿ�ĵ�ַδ֪

    //�����ͷ���Ӳ����ַ��SendHa������Ϊ����������MAC��ַ
    for (int i = 0; i < 6; i++)
        ARPFrame.SendHa[i] = 0x66;

    ARPFrame.FrameHeader.FrameType = htons(0x806);//֡����ΪARP
    ARPFrame.HardwareType = htons(0x0001);//Ӳ������Ϊ��̫��
    ARPFrame.ProtocolType = htons(0x0800);//Э������ΪIP
    ARPFrame.HLen = 6;//Ӳ����ַ����Ϊ6
    ARPFrame.PLen = 4;//Э���ַ��Ϊ4
    ARPFrame.Operation = htons(0x0001);//����ΪARP����

    std::cout << "ѡ�����ӷ�ʽ������0��Զ��1����";
    int model;
    cin >> model;

    if (model == 0) {
        ARPFrame.SendIP = htonl(0x70707070);//���������ϰ󶨵�IP��ַ
        //ѭ�����������豸�ĵ�ַ��Ϣ���ҵ� IPv4 ��ַ�������õ�ַ����Ϊ ARP ���ݰ��Ľ��շ�IP��ַ��
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
                        break;  // �ҵ� MAC ��ַ���˳�
                    }
                }
            }
        }

        ARPFrame.SendIP = IPPacket->SendIP;//������IP��ֵ�����ݱ���ԴIP
        ARPFrame.RecvIP = inet_addr(addr);
        
        for (int i = 0; i < 6; i++)
        {
            ARPFrame.SendHa[i] = ARPFrame.FrameHeader.SrcMAC[i] = IPPacket->SendHa[i];
        }
    }


    pcap_sendpacket(handle, (u_char*)&ARPFrame, sizeof(ARPFrame_t));

    std::cout << "ARP�����ͳɹ�" << endl;

    while (true)
    {
       int rtn = pcap_next_ex(handle, &pkt_header, &pkt_data);//pcap_next_ex ���ڲ�����һ�����ݰ�
       if (rtn == -1) {
           std::cout << "�������ݰ�����" << errbuf << endl;
           return 1;
       }
       else if (rtn == 0) {
           std::cout << "û�в�����Ч���ݰ�" << endl;
       }
       else {
           IPPacket = (ARPFrame_t*)pkt_data;
           if (ntohs(IPPacket->FrameHeader.FrameType) == 0x806) {
               if (memcmp(IPPacket->FrameHeader.SrcMAC, ARPFrame.FrameHeader.SrcMAC, 6) != 0) {
                   //���յ��� ARP ��Ӧ�е�Դ MAC ��ַ�뷢�� ARP ����ʱ���õ�Դ MAC ��ַ
                   // ����һ��ʼ���͵Ĺ㲥 ARP ����
                   printf(" MAC��ַΪ:");
                   // ��� MAC ��ַ
                   for (int i = 0; i < 6; i++) {
                       printf("%02x.", IPPacket->FrameHeader.SrcMAC[i]);
                   }
                   break;  // �ҵ� MAC ��ַ���˳�
               }
           }
       }
    }
    
    return 0;
}