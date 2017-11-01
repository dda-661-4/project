#include "sniffer.h"
#include "ui_sniffer.h"
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <pcap.h>


Sniffer::Sniffer(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::Sniffer)
{
    ui->setupUi(this);
}

Packet::Packet()
{
    m_data=NULL;
}

Packet::Packet(const Packet &p)
{
    pHeader=p.pHeader;
    m_data=new char [pHeader.caplen];
    memcpy(p.m_data,m_data,pHeader.caplen);
}
//прототип конструктор копирования
void operator=(const Packet &p)
{
    pHeader=p.pHeader;
    m_data=new char [pHeader.caplen];
    memcpy(p.m_data,m_data,pHeader.caplen);
}
// оператор присваивания
// функция (селектор)

Packet::~Packet()
{
    if (m_data!=NULL);
    delete []m_data;
}

Sniffer::~Sniffer()
{

    delete ui;
}

int z;

void Sniffer::on_actionExit_triggered()
{
    this->close();
}

void Sniffer::on_ok_clicked()
{
    z=ui->ok->text().toInt();
}
