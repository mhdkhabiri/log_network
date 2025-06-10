#include "SnifferThread.h"
#include "ChartWidget.h"


int main(int argc, char* argv[]) {
    
    std::string iface = "lo"; 

    Packet_sniffer sniffer(iface);

    std::thread sniffer_thread(&Packet_sniffer::start_sniffing, &sniffer);
    sniffer_thread.join(); 
    QApplication app(argc, argv);
    MainWindow window;
    window.show();
    return app.exec();

    return 0;
}