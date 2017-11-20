#ifndef SNIFFER_H
#define SNIFFER_H

#include <QMainWindow>
#include "dribl.h"
#include <QVector>

namespace Ui {
class Sniffer;
}

struct pkt
{
        qint32 t1;
        qint32 t2;
        qint32 caplen;
        qint32 len;
};

class header
{
public:
  pkt pHeader;
  unsigned char *m_data;

  //~header();
 private slots:

};

struct pcapHeader
{
    qint32 magic;
    qint16 version_major;
    qint16 version_minor;
    qint32 thiszone;     /* gmt to local correction */
    qint32 sigfigs;    /* accuracy of timestamps */
    qint32 snaplen;    /* max length saved portion of each pkt */
    qint32 linktype;   /* data link type (LINKTYPE_*) */
};

class PacketStream
{
public:
    pcapHeader fHeader;
    QVector <header> packets;
};

class Sniffer : public QMainWindow
{
    Q_OBJECT

public:
    explicit Sniffer(QWidget *parent = 0);
    int z1;
    bool flag_ip;
    ~Sniffer();   

private slots:

    void on_actionExit_triggered();

    void on_ok_clicked();

    void on_open_clicked();

    void on_pushButton_2_clicked();

    bool is_ip(int z1);

    void protocol_process(unsigned char ptr[],int z1);

    void protocol_ip(unsigned char ptr[]);

    void unknown_protocol(unsigned char ptr[],int z1);

    void print_data(unsigned char ptr[],int k,int len_poc);


private:
    Ui::Sniffer *ui;

};

#endif // SNIFFER_H
