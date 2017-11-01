#ifndef SNIFFER_H
#define SNIFFER_H

#include <QMainWindow>
#include "dribl.h"
#include <QVector>
#include <QObject>

namespace Ui {
class Sniffer;
}

struct PcapHeader
{
    qint32 t1;
    qint32 t2;
    qint32 caplen;
    qint32 len;

};

class Packet
{
public:

    Packet();
    Packet(const Packet &p); //прототип конструктор копирования
    void operator=(const Packet &p);// оператор присваивания
    // функция (селектор)

    char* getPcapHeader()
    {
        return (char*) &pHeader;
    };
    char* getData()
    {
        return (char*)m_data;
    };

    ~Packet();
    virtual void show();

 private:
    PcapHeader pHeader; // m -member
    unsigned char *m_data;
};

struct PcaFHeader
{
    qint32 magic;
    qint16 version_major;
    qint16 version_minor;
    qint32 thiszone;
    qint32 sigfigs;
    qint32 snaplen;
    qint32 linktype;
};

class PacketStream
{
 public:
    PcaFHeader fHeader;
    QVector <Packet> packets;
};


class Sniffer : public QMainWindow
{
    Q_OBJECT

public:
    explicit Sniffer(QWidget *parent = 0);
    ~Sniffer();

private slots:


    void on_actionExit_triggered();

    void on_ok_clicked();

private:
    Ui::Sniffer *ui;
};

#endif // SNIFFER_H
