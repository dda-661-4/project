#include "dribl.h"
#include "ui_dribl.h"
#include "mainwindow.h"
#include "sniffer.h"

MainWindow* openWindow;
Sniffer* openSniffer;

dribl::dribl(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::dribl)
{
    ui->setupUi(this);
    openWindow=new MainWindow();
    connect(ui->actionCalculator,SIGNAL(triggered()),this,SLOT(open()));

    openSniffer=new Sniffer();
    connect(ui->actionSniffer,SIGNAL(triggered()),this,SLOT(openSniff()));
}

dribl::~dribl()
{
    delete ui;
}

void dribl::open()
{
 openWindow->show();
}

void dribl::openSniff()
{
  openSniffer->show();
}



