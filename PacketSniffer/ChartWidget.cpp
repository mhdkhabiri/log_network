#include "ChartWidget.h"
#include <QVBoxLayout>
#include <QHeaderView>
#include <QThread>

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {
    // Set up the table widget
    tableWidget = new QTableWidget(this);
    tableWidget->setColumnCount(5);
    tableWidget->setHorizontalHeaderLabels({"Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol"});
    tableWidget->horizontalHeader()->setStretchLastSection(true);
    tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
    tableWidget->setSelectionMode(QAbstractItemView::SingleSelection);

    // Set up the layout
    QWidget* centralWidget = new QWidget(this);
    QVBoxLayout* layout = new QVBoxLayout(centralWidget);
    layout->addWidget(tableWidget);
    setCentralWidget(centralWidget);

    // Initialize the sniffer
    sniffer = new Packet_sniffer("lo", this); // Use "lo" for loopback interface
    connect(sniffer, &Packet_sniffer::packetCaptured, this, &MainWindow::addPacketToTable);

    // Run sniffer in a separate thread
    QThread* snifferThread = new QThread(this);
    sniffer->moveToThread(snifferThread);
    connect(snifferThread, &QThread::started, sniffer, &Packet_sniffer::start_sniffing);
    snifferThread->start();

    setWindowTitle("Packet Sniffer");
    resize(800, 600);
}

void MainWindow::addPacketToTable(const QString& src_ip, const QString& dst_ip, int src_port, int dst_port, const QString& protocol) {
    int row = tableWidget->rowCount();
    tableWidget->insertRow(row);
    tableWidget->setItem(row, 0, new QTableWidgetItem(src_ip));
    tableWidget->setItem(row, 1, new QTableWidgetItem(QString::number(src_port)));
    tableWidget->setItem(row, 2, new QTableWidgetItem(dst_ip));
    tableWidget->setItem(row, 3, new QTableWidgetItem(QString::number(dst_port)));
    tableWidget->setItem(row, 4, new QTableWidgetItem(protocol));
    tableWidget->scrollToBottom();
}