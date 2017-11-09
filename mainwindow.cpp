#include "mainwindow.h"
#include "ui_mainwindow.h"


MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}

bool plus = false;
bool minus = false;
bool devide = false;
bool multication = false;
double a,b,c;
int d;

void MainWindow::on_pushButton_clicked()
{
    ui->lineEdit->setText(ui->lineEdit->text()+"7");
}

void MainWindow::on_pushButton_4_clicked()
{
    ui->lineEdit->setText(ui->lineEdit->text()+"4");
}

void MainWindow::on_pushButton_7_clicked()
{
    ui->lineEdit->setText(ui->lineEdit->text()+"1");
}

void MainWindow::on_pushButton_2_clicked()
{
    ui->lineEdit->setText(ui->lineEdit->text()+"8");
}

void MainWindow::on_pushButton_5_clicked()
{
    ui->lineEdit->setText(ui->lineEdit->text()+"5");
}

void MainWindow::on_pushButton_8_clicked()
{
    ui->lineEdit->setText(ui->lineEdit->text()+"2");
}

void MainWindow::on_pushButton_3_clicked()
{
    ui->lineEdit->setText(ui->lineEdit->text()+"9");
}

void MainWindow::on_pushButton_6_clicked()
{
    ui->lineEdit->setText(ui->lineEdit->text()+"6");
}

void MainWindow::on_pushButton_9_clicked()
{
    ui->lineEdit->setText(ui->lineEdit->text()+"3");
}

void MainWindow::on_pushButton_11_clicked()
{
    a=ui->lineEdit->text().toDouble();
    plus=true;
    ui->lineEdit->setText("");
}

void MainWindow::on_pushButton_13_clicked()
{
    b=ui->lineEdit->text().toDouble();
    if(plus==true)
      {
       c=a+b;
       ui->lineEdit->setText(QString::number(c));
      }
    if(minus==true)
      {
       c=a-b;
       ui->lineEdit->setText(QString::number(c));
      }
    if(multication==true)
       {
       c=a*b;
       ui->lineEdit->setText(QString::number(c));
       }
    if(devide==true)
       {
         if(b!=0)
         {
       c=a/b;
       ui->lineEdit->setText(QString::number(c));
         }
        else
       ui->lineEdit->setText("Division is denied");
       }
     plus = false;
     minus = false;
     devide = false;
     multication = false;
}

void MainWindow::on_pushButton_12_clicked()
{
    a=ui->lineEdit->text().toDouble();
    minus=true;
    ui->lineEdit->setText("");
}

void MainWindow::on_pushButton_14_clicked()
{
    a=ui->lineEdit->text().toDouble();
    devide=true;
    ui->lineEdit->setText("");
}


void MainWindow::on_pushButton_15_clicked()
{
   ui->lineEdit->setText(ui->lineEdit->text()+"0");
}

void MainWindow::on_pushButton_16_clicked()
{
    a=ui->lineEdit->text().toDouble();
    multication=true;
    ui->lineEdit->setText("");
}


void MainWindow::on_actionExit_triggered()
{
    this->close();
}

void MainWindow::on_pushButton_17_clicked()
{
    d=ui->lineEdit->text().toDouble();
    d=d/10;
    ui->lineEdit->setText(QString::number(d));
}

void MainWindow::on_pushButton_10_clicked()
{
    ui->lineEdit->setText("");
}
