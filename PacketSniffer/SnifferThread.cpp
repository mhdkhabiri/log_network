#include "SnifferThread.h"

void Packet_sniffer::start_sniffing() {
    char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
        if (!handle) {
            std::cerr << "pcap_open_live failed: " << errbuf << std::endl;
            return;
        }

        struct bpf_program fp;
        if (pcap_compile(handle, &fp, "ip", 0, PCAP_NETMASK_UNKNOWN) == -1) {
            std::cerr << "pcap_compile failed" << std::endl;
            pcap_close(handle);
            return;
        }
        pcap_setfilter(handle, &fp);

        pcap_loop(handle, 0, Packet_sniffer::packet_handler, nullptr);

        pcap_freecode(&fp);
        pcap_close(handle);
}


void Packet_sniffer::packet_handler(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
    const struct ip* ip_hdr = (struct ip*)(packet + 14); 
    std::string src_ip = inet_ntoa(ip_hdr->ip_src);
    std::string dst_ip = inet_ntoa(ip_hdr->ip_dst);
    uint8_t proto = ip_hdr->ip_p;
    if (proto == IPPROTO_TCP) {
        const struct tcphdr* tcp_hdr = (struct tcphdr*)(packet + 14 + ip_hdr->ip_hl * 4);
        std::cout << "[TCP] " << src_ip << ":" << ntohs(tcp_hdr->th_sport)
                  << " -> " << dst_ip << ":" << ntohs(tcp_hdr->th_dport) << std::endl;
    } else if (proto == IPPROTO_UDP) {
        const struct udphdr* udp_hdr = (struct udphdr*)(packet + 14 + ip_hdr->ip_hl * 4);
        std::cout << "[UDP] " << src_ip << ":" << ntohs(udp_hdr->uh_sport)
                  << " -> " << dst_ip << ":" << ntohs(udp_hdr->uh_dport) << std::endl;
    }
}