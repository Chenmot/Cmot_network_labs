#include <iostream>
#include "pcap.h"
#include <WinSock2.h>  // 调用ntohs和htons函数

// 定义以太网头部结构
#pragma pack(1)
struct Ethead {
    uint8_t Ethdst[6];  // 目的以太网地址
    uint8_t Ethsrc[6];  // 源以太网地址
    uint16_t Type;   // 以太网类型
};


struct IPhead {
    uint8_t Headlength : 4;  // 首部长度
    uint8_t Version : 4;        // 版本
    uint8_t Servtype;                   // 服务类型
    uint16_t Totalleng;         // 总长度
    uint16_t Id;                // 标识
    uint16_t Offset;            // 片偏移
    uint8_t Livetime;                   // 存活时间
    uint8_t Protocolty;           // 协议类型（TCP或UDP）
    uint16_t Headchecksum;          // 首部校验和
    struct in_addr SrcIP;      // 源IP
    struct in_addr DstIP; // 目的IP
};


void packet_handler(unsigned char* user_data, const struct pcap_pkthdr* pkthdr, const unsigned char* packet) {
    const unsigned char* eth_header = packet;

    // 源MAC地址
    std::cout << "源MAC地址: ";
    for (int i = 0; i < 6; ++i) {
        printf("%02X", eth_header[i]);
        if (i < 5) std::cout << ":";
    }
    std::cout << std::endl;

    // 目的MAC地址
    std::cout << "目的MAC地址: ";
    for (int i = 6; i < 12; ++i) {
        printf("%02X", eth_header[i]);
        if (i < 11) std::cout << ":";
    }
    std::cout << std::endl;

    // 以太网类型/长度
    int ethertype = (eth_header[12] << 8) | eth_header[13];
    std::cout << "以太网类型: 0x" << std::hex << ethertype << std::dec << std::endl;

    if (ethertype == 0x0800) { // IPv4
        const IPhead* ip_protocol = reinterpret_cast<const IPhead*>(eth_header + 14); // 跳过以太网头部

        // 输出IP头部信息
        std::cout << "IP数据包报文解析如下：\n";
        printf("  IP版本: IPv%d\n", ip_protocol->Version);
        int header_length = ip_protocol->Headlength * 4;
        std::cout << "  IP协议首部长度: " << header_length << " bytes\n";
        printf("  服务类型: %d\n", ip_protocol->Servtype);
        std::cout << "  数据包总长度: " << ntohs(ip_protocol->Totalleng) << " bytes\n";
        std::cout << "  标识: " << ntohs(ip_protocol->Id) << "\n";
        int offset = ntohs(ip_protocol->Offset);
        std::cout << "  片偏移: " << (offset & 0x1FFF) * 8 << "\n";
        std::cout << "  生存时间: " << int(ip_protocol->Livetime) << "\n";
        std::cout << "  首部检验和: " << htons(ip_protocol->Headchecksum) << "\n";

        char src[17]; // 存放源IP地址
        ::inet_ntop(AF_INET, &(ip_protocol->SrcIP), src, 17);
        std::cout << "  源IP地址: " << src << "\n";

        char dst[17]; // 存放目的IP地址
        ::inet_ntop(AF_INET, &(ip_protocol->DstIP), dst, 17);
        std::cout << "  目的IP: " << dst << "\n";

        printf("  协议号: %d\n", ip_protocol->Protocolty);
    }

    std::cout << std::endl;
}


int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    // 获取可用网络设备列表
    pcap_if_t* alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "查找设备时出错: " << errbuf << std::endl;
        return 1;
    }

    // 列出可用网络设备并让用户选择一个
    int count = 1;
    pcap_if_t* device = alldevs;
    while (device != nullptr) {
        std::cout << count << ". " << device->name << " - " << device->description << std::endl;
        device = device->next;
        count++;
    }

    int selected_device;
    std::cout << "选择一个设备（1-" << count - 1 << "）: ";
    std::cin >> selected_device;

    device = alldevs;
    for (int i = 1; i < selected_device; i++) {
        device = device->next;
    }

    // 打开选择的网络设备
    pcap_t* handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        std::cerr << "打开设备时出错: " << errbuf << std::endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

    // 用户输入数据包过滤表达式
    std::string filter_exp;
    std::cout << "请输入数据包过滤表达式 (e.g., 'ip and udp'): ";
    std::cin >> filter_exp;

    // 设置数据包过滤器
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "编译过滤器时出错: " << pcap_geterr(handle) << std::endl;
        pcap_freealldevs(alldevs);
        pcap_close(handle);
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "设置过滤器时出错: " << pcap_geterr(handle) << std::endl;
        pcap_freealldevs(alldevs);
        pcap_close(handle);
        return 1;
    }

    // 开始捕获数据包，使用 packet_handler 回调函数进行分析
    //pcap_loop(handle, 0, packet_handler, NULL);
    pcap_loop(handle, 10, packet_handler, NULL);

    // 关闭捕获器和释放资源
    pcap_freealldevs(alldevs);
    pcap_close(handle);

    return 0;
}