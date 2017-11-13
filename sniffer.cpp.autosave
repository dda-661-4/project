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

Sniffer::~Sniffer()
{
    delete ui;
}

int buff[2000000];
QString fName;
header pk;
int k;
int i;
char *m_data;

void Sniffer::on_actionExit_triggered()
{
    this->close();
}

void Sniffer::on_ok_clicked()
{   
    int z;
    ui->pack->setText("");
    char *p_data;
    QFile file(fName);
    z=ui->ok->text().toInt(); 
    file.seek(buff[z]);
    file.read((char*)&pk.pHeader,16);
    p_data=new char [pk.pHeader.len];
    file.read(p_data,pk.pHeader.len);
    for(int i = 0;i < pk.pHeader.len; i++)
    {
      QString d;
      d=QString::number(p_data[i]);
      int q=d.toInt();
      QString s=QString::number(q,16).toUpper();
      ui->pack->insertPlainText(" "+ s);
    }
}

void Sniffer::on_open_clicked()
{
  fName = QFileDialog::getOpenFileName(this,"open the file");
  QFile file(fName);
  PacketStream ps;

  if (!file.open(QIODevice::ReadOnly))
      {
              qDebug() << "error open file";
      }
  else
  {
  file.read((char *)&ps.fHeader,24);

    int p=file.size();
    int allpackets=0;
    int min=65535;
    int max=0;
    //char *m_data;

     i=0;
    while(file.pos()<p)
   {
     allpackets++;
     buff[allpackets]=file.pos();
     file.read((char*)&pk.pHeader,16);
     m_data=new  char [pk.pHeader.len];
     file.read(m_data,pk.pHeader.len);
     ps.packets.push_back((header()));
     ps.packets[i].pHeader.t1=pk.pHeader.t1;
     ps.packets[i].pHeader.t2=pk.pHeader.t2;
     ps.packets[i].pHeader.len=pk.pHeader.len;
     ps.packets[i].pHeader.caplen=pk.pHeader.caplen;
     k=i;
     i++;
    for(int i = 0;i < pk.pHeader.len; i++)
    {
        QString d;
        d=QString::number(m_data[i]);
        int q=d.toInt();
        QString s=QString::number(q,16).toUpper();
        ui->pack->insertPlainText(" "+ s);
    }

    if(pk.pHeader.caplen>max)
     {
       max=pk.pHeader.caplen;
     }
     if(pk.pHeader.caplen<min)
     {
       min=pk.pHeader.caplen;
     }

     if (m_data!=NULL)
     {
     delete []m_data;
     }
   }
    for(int i = 0;i < k; i++)
    {
     ui->textEdit->append("packets #" + QString::number(i));
     ui->textEdit->append("t1\t" + QString::number(ps.packets[i].pHeader.t1));
      ui->textEdit->append("t2\t" + QString::number(ps.packets[i].pHeader.t2));
       ui->textEdit->append("len\t" + QString::number(ps.packets[i].pHeader.len));
        ui->textEdit->append("caplen\t" + QString::number(ps.packets[i].pHeader.caplen));
    }
     ui->min->setText(QString::number(min));
     ui->max->setText(QString::number(max));
     }
  }

void Sniffer::on_pushButton_2_clicked()
{
     ui->pack->setText("");
     ui->textEdit->setText("");
     ui->max->setText("");
     ui->min->setText("");
}
