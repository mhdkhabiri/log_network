#ifndef SNIFFERTHREAD_H
#define SNIFFERTHREAD_H

#include <QObject>
#include <QString>
#include <QMutex>
#include <memory>
#include <queue>
#include <string>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

// Structure to hold packet data
struct RawPacket {
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    std::string protocol;

    RawPacket(const std::string& src, const std::string& dst, uint16_t sport, uint16_t dport, const std::string& proto)
        : src_ip(src), dst_ip(dst), src_port(sport), dst_port(dport), protocol(proto) {}
};

class Packet_sniffer : public QObject {
    Q_OBJECT

public:
    explicit Packet_sniffer(const std::string& iface, QObject* parent = nullptr);
    void start_sniffing();
    std::shared_ptr<RawPacket> get_next_packet(); // Get packet from queue

signals:
    void packetCaptured(const QString& src_ip, const QString& dst_ip, int src_port, int dst_port, const QString& protocol);

private:
    static void packet_handler(u_char* args, const struct pcap_pkthdr* header, const u_char* packet);
    void process_packet(const struct pcap_pkthdr* header, const u_char* packet);

    std::string interface;
    std::queue<std::shared_ptr<RawPacket>> packet_queue; // Queue to store packets
    QMutex queue_mutex; // Mutex for thread-safe queue access
};

#endif // SNIFFERTHREAD_H