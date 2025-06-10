#include "SnifferThread.h"


int main() {
    // std::string iface = "eth0"; // Change to your interface, e.g., wlan0
    std::string iface = "lo"; // For WiFi

    Packet_sniffer sniffer(iface);

    std::thread sniffer_thread(&Packet_sniffer::start_sniffing, &sniffer);
    sniffer_thread.join(); // In real apps: detach or add signal handlers

    return 0;
}