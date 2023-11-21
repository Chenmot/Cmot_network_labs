#include <iostream>
#include "pcap.h"
#include <WinSock2.h>  // ����ntohs��htons����

// ������̫��ͷ���ṹ
#pragma pack(1)
struct Ethead {
    uint8_t Ethdst[6];  // Ŀ����̫����ַ
    uint8_t Ethsrc[6];  // Դ��̫����ַ
    uint16_t Type;   // ��̫������
};


struct IPhead {
    uint8_t Headlength : 4;  // �ײ�����
    uint8_t Version : 4;        // �汾
    uint8_t Servtype;                   // ��������
    uint16_t Totalleng;         // �ܳ���
    uint16_t Id;                // ��ʶ
    uint16_t Offset;            // Ƭƫ��
    uint8_t Livetime;                   // ���ʱ��
    uint8_t Protocolty;           // Э�����ͣ�TCP��UDP��
    uint16_t Headchecksum;          // �ײ�У���
    struct in_addr SrcIP;      // ԴIP
    struct in_addr DstIP; // Ŀ��IP
};


void packet_handler(unsigned char* user_data, const struct pcap_pkthdr* pkthdr, const unsigned char* packet) {
    const unsigned char* eth_header = packet;

    // ԴMAC��ַ
    std::cout << "ԴMAC��ַ: ";
    for (int i = 0; i < 6; ++i) {
        printf("%02X", eth_header[i]);
        if (i < 5) std::cout << ":";
    }
    std::cout << std::endl;

    // Ŀ��MAC��ַ
    std::cout << "Ŀ��MAC��ַ: ";
    for (int i = 6; i < 12; ++i) {
        printf("%02X", eth_header[i]);
        if (i < 11) std::cout << ":";
    }
    std::cout << std::endl;

    // ��̫������/����
    int ethertype = (eth_header[12] << 8) | eth_header[13];
    std::cout << "��̫������: 0x" << std::hex << ethertype << std::dec << std::endl;

    if (ethertype == 0x0800) { // IPv4
        const IPhead* ip_protocol = reinterpret_cast<const IPhead*>(eth_header + 14); // ������̫��ͷ��

        // ���IPͷ����Ϣ
        std::cout << "IP���ݰ����Ľ������£�\n";
        printf("  IP�汾: IPv%d\n", ip_protocol->Version);
        int header_length = ip_protocol->Headlength * 4;
        std::cout << "  IPЭ���ײ�����: " << header_length << " bytes\n";
        printf("  ��������: %d\n", ip_protocol->Servtype);
        std::cout << "  ���ݰ��ܳ���: " << ntohs(ip_protocol->Totalleng) << " bytes\n";
        std::cout << "  ��ʶ: " << ntohs(ip_protocol->Id) << "\n";
        int offset = ntohs(ip_protocol->Offset);
        std::cout << "  Ƭƫ��: " << (offset & 0x1FFF) * 8 << "\n";
        std::cout << "  ����ʱ��: " << int(ip_protocol->Livetime) << "\n";
        std::cout << "  �ײ������: " << htons(ip_protocol->Headchecksum) << "\n";

        char src[17]; // ���ԴIP��ַ
        ::inet_ntop(AF_INET, &(ip_protocol->SrcIP), src, 17);
        std::cout << "  ԴIP��ַ: " << src << "\n";

        char dst[17]; // ���Ŀ��IP��ַ
        ::inet_ntop(AF_INET, &(ip_protocol->DstIP), dst, 17);
        std::cout << "  Ŀ��IP: " << dst << "\n";

        printf("  Э���: %d\n", ip_protocol->Protocolty);
    }

    std::cout << std::endl;
}


int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    // ��ȡ���������豸�б�
    pcap_if_t* alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "�����豸ʱ����: " << errbuf << std::endl;
        return 1;
    }

    // �г����������豸�����û�ѡ��һ��
    int count = 1;
    pcap_if_t* device = alldevs;
    while (device != nullptr) {
        std::cout << count << ". " << device->name << " - " << device->description << std::endl;
        device = device->next;
        count++;
    }

    int selected_device;
    std::cout << "ѡ��һ���豸��1-" << count - 1 << "��: ";
    std::cin >> selected_device;

    device = alldevs;
    for (int i = 1; i < selected_device; i++) {
        device = device->next;
    }

    // ��ѡ��������豸
    pcap_t* handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        std::cerr << "���豸ʱ����: " << errbuf << std::endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

    // �û��������ݰ����˱��ʽ
    std::string filter_exp;
    std::cout << "���������ݰ����˱��ʽ (e.g., 'ip and udp'): ";
    std::cin >> filter_exp;

    // �������ݰ�������
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "���������ʱ����: " << pcap_geterr(handle) << std::endl;
        pcap_freealldevs(alldevs);
        pcap_close(handle);
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "���ù�����ʱ����: " << pcap_geterr(handle) << std::endl;
        pcap_freealldevs(alldevs);
        pcap_close(handle);
        return 1;
    }

    // ��ʼ�������ݰ���ʹ�� packet_handler �ص��������з���
    //pcap_loop(handle, 0, packet_handler, NULL);
    pcap_loop(handle, 10, packet_handler, NULL);

    // �رղ��������ͷ���Դ
    pcap_freealldevs(alldevs);
    pcap_close(handle);

    return 0;
}