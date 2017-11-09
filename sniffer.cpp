#include "sniffer.h"
#include "ui_sniffer.h"
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <pcap.h>
#include <QFileDialog>
#include <QDebug>
#include <QTextStream>


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
  QFile fileOut("/home/dribl/d.txt");
  PacketStream ps;
  header pk;

  if (!file.open(QIODevice::ReadOnly))
      {
              qDebug() << "error open file";
      }
  else
  {
  file.read((char *)&ps.fHeader,24);
  int p=file.size();
  int allpackets=0;
  if(fileOut.open(QIODevice::WriteOnly | QIODevice::Text))
  {
    QTextStream writeStream(&fileOut);
    writeStream << ps.fHeader.linktype<<endl;
    writeStream << ps.fHeader.snaplen<<endl;
    writeStream << ps.fHeader.sigfigs<<endl;
    writeStream << ps.fHeader.thiszone<<endl;
    writeStream << ps.fHeader.version_major<<endl;
    writeStream << ps.fHeader.version_minor<<endl;

    while(file.pos()<p)
   {
     allpackets++;
     file.read((char*)&pk.pHeader,16);

     writeStream << allpackets<<endl;
     writeStream <<"len bytes"<<pk.pHeader.len<<endl;
     writeStream << "caplen bytes"<<pk.pHeader.caplen<<endl;
     file.seek(file.pos()+pk.pHeader.len);
   }
    QFile File("/home/dribl/d.txt");
    if((File.exists())&&(File.open(QIODevice::ReadOnly)))
       {
       ui->textBrowser->setText(File.readAll());
       }
  }
 }

  qDebug() << ps.fHeader.linktype;
  qDebug() << ps.fHeader.magic;
  qDebug() << ps.fHeader.sigfigs;
  qDebug() << ps.fHeader.snaplen;
  qDebug() << ps.fHeader.thiszone;
  qDebug() << ps.fHeader.version_major;
  qDebug() << ps.fHeader.version_minor;

}

void Sniffer::on_pushButton_2_clicked()
{
     ui->textBrowser->setText("");
}
