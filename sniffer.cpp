#include "sniffer.h"
#include "ui_sniffer.h"
#include <iostream>
#include <stdio.h>
#include <QFileDialog>
#include <QDebug>
#include <QTextStream>
#include <QVector>


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
int allpackets;

void Sniffer::on_actionExit_triggered()
{
    this->close();
}

PacketStream ps;
void Sniffer::on_ok_clicked()
{    
    int z;
    ui->pack->setText("");
    z=ui->ok->text().toInt();
    for(int i = 0;i <ps.packets[z].pHeader.caplen; i++)
   {
     QString d;
     d=QString::number(ps.packets[z].A[i]);
     int q=d.toInt();
     QString s=QString::number(q,16).toUpper();
     ui->pack->insertPlainText(" "+ s);
    }
}

void Sniffer::on_open_clicked()
{
  fName = QFileDialog::getOpenFileName(this,"open the file");
  QFile file(fName);

  if (!file.open(QIODevice::ReadOnly))
      {
         qDebug() << "error open file";
      }
  else
  {
  file.read((char *)&ps.fHeader,24);

  ui->textEdit->append("linktype\t" + QString::number(ps.fHeader.linktype));
  ui->textEdit->append("max lenth bytes\t" + QString::number(ps.fHeader.snaplen)) ;
  ui->textEdit->append("sigfigs\t" + QString::number(ps.fHeader.sigfigs)) ;
  ui->textEdit->append("thiszone\t" + QString::number( ps.fHeader.thiszone));
  ui->textEdit->append("major\t" + QString::number(ps.fHeader.version_major)) ;
  ui->textEdit->append("minor\t" + QString::number( ps.fHeader.version_minor)) ;
  ui->textEdit->append("magic\t" + QString::number( ps.fHeader.magic)) ;
  ui->textEdit->append("\n\n\n") ;

    int p=file.size();
    allpackets=0;
    int min=65535;
    int max=0;
     i=0;
    while(file.pos()<p)
   {
       allpackets++;
       buff[allpackets]=file.pos();
       file.read((char*)&pk.pHeader,16);
      // m_data=new char [pk.pHeader.len];
       file.read((char*)&pk.A,pk.pHeader.len);
       ps.packets.append(pk);
       k=i;

      /*for(int k = 0;k<pk.pHeader.len;k++)
       {
        QString d;
        d=QString::number(pk.A[k]);
        int q=d.toInt();
        QString s=QString::number(q,16).toUpper();
        ui->pack->insertPlainText(" "+ s);
       }*/

    if(pk.pHeader.caplen>max)
     {
       max=pk.pHeader.caplen;
     }
     if(pk.pHeader.caplen<min)
     {
       min=pk.pHeader.caplen;
     }
     ui->textEdit->append("packets #" + QString::number(i));
     ui->textEdit->append("t1\t" + QString::number(pk.pHeader.t1));
     ui->textEdit->append("t2\t" + QString::number(pk.pHeader.t2));
     ui->textEdit->append("len\t" + QString::number(pk.pHeader.len));
     ui->textEdit->append("caplen\t" + QString::number(pk.pHeader.caplen));
      i++;
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
