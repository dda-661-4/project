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

    ui->tableWidget->setColumnCount(8);
      ui->data_table->setColumnCount(10000);
    ui->tableWidget->setRowCount(100000);
      ui->data_table->setRowCount(10000);
    ui->tableWidget->setShowGrid(true);
      ui->data_table->setShowGrid(true);
    ui->tableWidget->setHorizontalHeaderItem(0,new QTableWidgetItem(tr("mac destination")));
    ui->tableWidget->setHorizontalHeaderItem(1,new QTableWidgetItem(tr("mac source")));
    ui->tableWidget->setHorizontalHeaderItem(2,new QTableWidgetItem(tr("type")));
    ui->tableWidget->setHorizontalHeaderItem(3,new QTableWidgetItem(tr("PROTOCOL")));
    ui->tableWidget->setHorizontalHeaderItem(4,new QTableWidgetItem(tr("IP source")));
    ui->tableWidget->setHorizontalHeaderItem(5,new QTableWidgetItem(tr("IP destination")));
    ui->tableWidget->setHorizontalHeaderItem(6,new QTableWidgetItem(tr("ports source")));
    ui->tableWidget->setHorizontalHeaderItem(7,new QTableWidgetItem(tr("ports destination")));
}

Sniffer::~Sniffer()
{
    delete ui;
}

QString fName,m;
header pk;
int k;
int i;
int allpackets;
int u;
QString p1,p2,p3,q1,q2,q3,S="0";
QString s1,s2,M;
unsigned char *ptr;
QTableWidgetItem *item;


void Sniffer::on_actionExit_triggered()
{
    this->close();
}

PacketStream ps;
void Sniffer::on_ok_clicked()
{
   u=ui->number->text().toInt();
   ui->pack->setText("");
   for(int i = 0;i < ps.packets[u].pHeader.caplen; i++)
   {
     QString d;
     d=QString::number(ps.packets[u].m_data[i]);
     int q=d.toInt();
     QString s=QString::number(q,16).toUpper();
     ui->pack->insertPlainText(" "+ s);
   }
}

void Sniffer::on_open_clicked()
{
  fName = QFileDialog::getOpenFileName(0,"open the file","","(*.cap)");
  QFile file(fName);

  if (!file.open(QIODevice::ReadOnly))
      {
         qDebug() << "error open file";
      }
  else
  {
  file.read((char *)&ps.fHeader,24);

 /* ui->textEdit->insertPlainText("linktype\t" + QString::number(ps.fHeader.linktype));
  ui->textEdit->append("max lenth bytes\t" + QString::number(ps.fHeader.snaplen)) ;
  ui->textEdit->append("sigfigs\t" + QString::number(ps.fHeader.sigfigs)) ;
  ui->textEdit->append("thiszone\t" + QString::number( ps.fHeader.thiszone));
  ui->textEdit->append("major\t" + QString::number(ps.fHeader.version_major)) ;
  ui->textEdit->append("minor\t" + QString::number( ps.fHeader.version_minor)) ;
  ui->textEdit->append("magic\t" + QString::number( ps.fHeader.magic)) ;
  ui->textEdit->append("\n\n\n") ;*/
    int p=file.size();
    allpackets=0;
    int min=65535;
    int max=0;
    i=0;
    int len_poc;

    while(file.pos()<p)
   {
       allpackets++;
       file.read((char*)&pk.pHeader,16);
       pk.m_data= new unsigned char[pk.pHeader.caplen];
       len_poc=pk.pHeader.caplen;
       ptr=pk.m_data;
       file.read((char*)pk.m_data,pk.pHeader.len);
       ps.packets.append(pk);  
       k=i;
      /*for(int k = 0;k<pk.pHeader.len;k++)
       {
        QString d;
        d=QString::number(pk.m_data[k]);
        int q=d.toInt();
        QString s=QString::number(q,16).toUpper();
        ui->pack->insertPlainText(" "+ s);
       }*/
       //qDebug()<<i;

       print_data(ptr,k,len_poc);

    if(pk.pHeader.caplen>max)
     {
       max=pk.pHeader.caplen;
     }
     if(pk.pHeader.caplen<min)
     {
       min=pk.pHeader.caplen;
     }

     item= new QTableWidgetItem;
     item->setText(QString::number(pk.m_data[0],16)+" " +QString::number(pk.m_data[1],16)+" "+QString::number(pk.m_data[2],16)+" "+QString::number(pk.m_data[3],16)+" "+QString::number(pk.m_data[4],16)+" "+" "+QString::number(pk.m_data[5],16));
     ui->tableWidget->setItem(k,0,item);


     item= new QTableWidgetItem;
     item->setText(QString::number(pk.m_data[6],16)+" " +QString::number(pk.m_data[7],16)+" "+QString::number(pk.m_data[8],16)+" "+QString::number(pk.m_data[9],16)+" "+QString::number(pk.m_data[10],16)+" "+" "+QString::number(pk.m_data[11],16));
     ui->tableWidget->setItem(k,1,item);

     s1=QString::number(pk.m_data[12]);

     s2=QString::number(pk.m_data[13]);

     M=s1+s2;

    item= new QTableWidgetItem;
    item->setText(M);
    ui->tableWidget->setItem(k,2,item);

     z1=M.toInt();

     //IP PROTOCOLS--------------------------------------------------------------------------------------

     protocol_process( ptr,z1);

     i++;
   }
    //--------------------------------------------
    ui->data_table->setRowCount(k);
    ui->tableWidget->setRowCount(k);
     ui->min->setText(QString::number(min));
     ui->max->setText(QString::number(max));
  }
  delete []pk.m_data;
 }

void Sniffer::on_pushButton_2_clicked()
{
     ui->pack->setText("");
     //ui->textEdit->setText("");
     ui->max->setText("");
     ui->min->setText("");
}

bool Sniffer::is_ip(int z1)
{
    if(z1==80)
   {
        item= new QTableWidgetItem;
        item->setText("IP");
        ui->tableWidget->setItem(k,3,item);
    return true;
   }
    else
   {
        item= new QTableWidgetItem;
        item->setText("-");
        ui->tableWidget->setItem(k,3,item);
    return false;
   }
}

void Sniffer::protocol_process(unsigned char ptr[],int z1)
{
    flag_ip=is_ip(z1);
    switch(flag_ip)
 {
  case true :    protocol_ip(ptr);
        break;
  case false :  unknown_protocol(ptr,z1);
         break;
 }
}

void Sniffer::protocol_ip(unsigned char ptr[])
 {

    // ui->textEdit->append("ip address source:");// 14 15 16 17 18 19 20 21 22 23 24 25| 26 27 28 29 30 31 32 33 |34 35

    item= new QTableWidgetItem;
    item->setText(QString::number(pk.m_data[26],10)+" " +QString::number(pk.m_data[27],10)+" "+QString::number(pk.m_data[28],10)+" "+QString::number(pk.m_data[29],10));
    ui->tableWidget->setItem(k,4,item);


     for(int i=26;i<30;i++)
     {
     //   ui->textEdit->insertPlainText(QString::number(ptr[i],10)+ " ");
     }
//
     //ui->textEdit->append("ip address destination:");

     item= new QTableWidgetItem;
     item->setText(QString::number(pk.m_data[30],10)+" " +QString::number(pk.m_data[31],10)+" "+QString::number(pk.m_data[32],10)+" "+QString::number(pk.m_data[33],10));
     ui->tableWidget->setItem(k,5,item);


     for(int i=30;i<34;i++)
     {
       //  ui->textEdit->insertPlainText(QString::number(ptr[i],10)+ " ");
     }

// PORTS================================================== -----------------------------------------------------------------------------------------------------------------
     //ui->textEdit->append("ports source-");
     QString m1,m2;
     m1=QString::number(pk.m_data[34]);
     int i1=m1.toInt();

     QString f1=QString::number(i1,16).toUpper();

     m2=QString::number(pk.m_data[35]);
     int i2=m2.toInt();
     QString f2=QString::number(i2,16).toUpper();
     m=f1+f2;
     m=QString::number(m.toInt(0,16),10);

     item= new QTableWidgetItem;
     item->setText(m);
     ui->tableWidget->setItem(k,6,item);

   //  ui->textEdit->insertPlainText(m);
//---------------------------------------------------------------------------------------------------------------------------
   // ui->textEdit->append("ports destination-");

    m1=QString::number(pk.m_data[36]);
    i1=m1.toInt();

    f1=QString::number(i1,16).toUpper();

    m2=QString::number(pk.m_data[35]);
    i2=m2.toInt();
     f2=QString::number(i2,16).toUpper();
    m=f1+f2;

    m=QString::number(m.toInt(0,16),10);

    item= new QTableWidgetItem;
    item->setText(m);
    ui->tableWidget->setItem(k,7,item);
   // ui->textEdit->insertPlainText(m);
 }

void Sniffer::unknown_protocol(unsigned char ptr[],int z1)
{

  // ui->textEdit->append("NOT IP");
}

void Sniffer::print_data(unsigned char ptr[],int k,int len_poc)
{
  for(int j=0;j<k;j++)
   for(int i=0;i<len_poc;i++)
   {
    item= new QTableWidgetItem;
    item->setText(QString::number(ptr[i],16));
    ui->data_table->setItem(j,i,item);
   }
  //ui->data_table->setColumnCount(len_poc);
}


