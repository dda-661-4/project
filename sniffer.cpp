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

    ui->textEdit->append("linktype\t" + QString::number(ps.fHeader.linktype));
    ui->textEdit->append("max lenth bytes\t" + QString::number(ps.fHeader.snaplen)) ;
    ui->textEdit->append("sigfigs\t" + QString::number(ps.fHeader.sigfigs)) ;
    ui->textEdit->append("thiszone\t" + QString::number( ps.fHeader.thiszone));
    ui->textEdit->append("major\t" + QString::number(ps.fHeader.version_major)) ;
    ui->textEdit->append("minor\t" + QString::number( ps.fHeader.version_minor)) ;
    ui->textEdit->append("magic\t" + QString::number( ps.fHeader.magic)) ;
    ui->textEdit->append("\n\n\n") ;


    int min=65535;
    int max=0;
    char *m_data;

    while(file.pos()<p)
   {
     allpackets++;
     file.read((char*)&pk.pHeader,16);
     qDebug()<<file.pos();
     m_data=new char [pk.pHeader.len];

     file.read(m_data,pk.pHeader.len);

     ui->textEdit->append("packets # " + QString::number(allpackets));
     ui->textEdit->append("t2\1" + QString::number(pk.pHeader.t1)) ;
     ui->textEdit->append("t2\2" + QString::number(pk.pHeader.t2)) ;


     for(int i = 0;i < pk.pHeader.len; i++)
    {
         QString d;
         d=QString::number(m_data[i]);
         int q=d.toInt();
         QString s=QString::number(q,16).toUpper();
         ui->pack->insertPlainText(" "+ s);
       // ui->pack->append(QString::number(m_data[i]&0xff));
    }

     ui->textEdit->append("packet : bytes\n" + QString::number(pk.pHeader.len));
     ui->textEdit->append("packet : bytes\n" + QString::number(pk.pHeader.caplen)) ;
     ui->textEdit->append("\n\n");

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
     ui->min->setText(QString::number(min));
     ui->max->setText(QString::number(max));

  }

 }


void Sniffer::on_pushButton_2_clicked()
{
     ui->textEdit->setText("");
     ui->max->setText("");
     ui->min->setText("");
     ui->pack->setText("");
}
