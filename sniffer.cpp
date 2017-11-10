#include "sniffer.h"
#include "ui_sniffer.h"
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <pcap.h>
#include <QFileDialog>
#include <QDebug>
#include <QTextStream>
#include <QVector>
#include <math.h>


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
 char *m_data;

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
    writeStream <<"linktype\t"<< ps.fHeader.linktype<<endl;
    writeStream <<"max lenth bytes\t"<< ps.fHeader.snaplen<<endl;
    writeStream <<"sigfigs\t"<< ps.fHeader.sigfigs<<endl;
    writeStream <<"thiszone\t"<< ps.fHeader.thiszone<<endl;
    writeStream <<"major\t"<< ps.fHeader.version_major<<endl;
    writeStream <<"minor\t"<< ps.fHeader.version_minor<<endl;
    writeStream <<"magic\t"<< ps.fHeader.magic<<endl;
    writeStream <<"\n\n\n";

    int min=65535;
    int max=0;

    while(file.pos()<p)
   {
     allpackets++;
     file.read((char*)&pk.pHeader,16);
     //qDebug()<<pk.pHeader.caplen;
     m_data=new char [pk.pHeader.len];
      //qDebug()<<file.pos();
     file.read(m_data,pk.pHeader.len);
      //qDebug()<<file.pos();
     /*ui->textBrowser->append("packets #"+QString::number(allpackets));
     ui->textBrowser->append("t1\t"+QString::number(pk.pHeader.t1));
     ui->textBrowser->append("t2\t"+QString::number(pk.pHeader.t2));*/
     writeStream << "packets # "<<allpackets<<endl;
     writeStream << "t1\t"<<pk.pHeader.t1<<endl;
     writeStream<< "t2\t"<< pk.pHeader.t2<<endl;

     for(int i = 0;i < pk.pHeader.len; i++)
    {
    // ui->textBrowser->append("DATA\t"+QString::number(m_data[i]&0xff));
     writeStream <<"DATA\t"<<hex<<(m_data[i]&0xff)<<endl;
    }
     /*ui->textBrowser->append("packet : bytes\n"+QString::number(pk.pHeader.len));
     ui->textBrowser->append("packet : bytes\n"+QString::number(pk.pHeader.caplen));
     ui->textBrowser->append("\n\n");*/
     writeStream <<"packet : bytes\n"<<pk.pHeader.len<<endl;
     writeStream <<"packet : bytes\n"<<pk.pHeader.caplen<<endl;
     writeStream <<"\n\n";

    if(pk.pHeader.caplen>max)
     {
        max=pk.pHeader.caplen;
     }
     if(pk.pHeader.caplen<min)
     {
         min=pk.pHeader.caplen;
     }

    //file.seek(file.pos()+pk.pHeader.len);
     if (m_data!=NULL)
     {
     delete []m_data;
     }
   }
     ui->min->setText(QString::number(min));
     ui->max->setText(QString::number(max));

   QFile File("/home/dribl/d.txt");
    if((File.exists())&&(File.open(QIODevice::ReadOnly)))
     {
       ui->textBrowser->setText(File.readAll());
     }
  }

  file.close();
 }

}

void Sniffer::on_pushButton_2_clicked()
{
     ui->textBrowser->setText("");
     ui->max->setText("");
     ui->min->setText("");
}
