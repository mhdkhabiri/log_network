#ifndef SNIFFERTHREAD_H
#define SNIFFERTHREAD_H

#include <iostream>
#include <thread>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <cstring>


class Packet_sniffer {
public:
    Packet_sniffer(const std::string& interface) : interface(interface) {}
    void start_sniffing();

private:
    std::string interface;
    static void packet_handler(u_char* args, const struct pcap_pkthdr* header, const u_char* packet);

};



#endif // SNIFFERTHREAD_H