#include "sniffer.h"
#include "ui_sniffer.h"
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <pcap.h>
#include <QFileDialog>
#include <QDebug>


Sniffer::Sniffer(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::Sniffer)
{
    ui->setupUi(this);
}

/*Packet::Packet()
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
*/
Sniffer::~Sniffer()
{

    delete ui;
}


int z;
int o=0;


void Sniffer::on_actionExit_triggered()
{
    this->close();
}

void Sniffer::on_ok_clicked()
{
    z=ui->ok->text().toInt();
}

void Sniffer::on_open_clicked()
{
  QString fName = QFileDialog::getOpenFileName(this,"open the file");
  QFile file(fName);
  PacketStream ps;
  header pk;

  if (!file.open(QIODevice::ReadOnly))
      {
              qDebug() << "error open file";
      }
  else {
  file.read((char *)&ps.fHeader,24);
  int p= file.size();
  qDebug() <<file.size();

  int allpackets=0;
  while(file.pos()<p)
   {
      qDebug() << file.pos();
      file.read((char*)&pk.pHeader,16);
      qDebug() << file.pos();
      allpackets++;
 //qDebug() << pk.pHeader.len;
  ui->textBrowser->setText(QString::number(allpackets));

  file.seek(file.pos()-16);
  file.seek(file.pos()+pk.pHeader.caplen);
   }
  }

/*qDebug() << ps.fHeader.linktype;
  qDebug() << ps.fHeader.magic;
  qDebug() << ps.fHeader.sigfigs;
  qDebug() << ps.fHeader.snaplen;
  qDebug() << ps.fHeader.thiszone;
  qDebug() << ps.fHeader.version_major;
  qDebug() << ps.fHeader.version_minor;
*/
}

void Sniffer::on_pushButton_2_clicked()
{
     ui->textBrowser->setText("");
}
