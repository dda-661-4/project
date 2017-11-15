#ifndef DRIBL_H
#define DRIBL_H

#include <QMainWindow>
#include "dribl.h"
#include "mainwindow.h"
#include "sniffer.h"

namespace Ui
{
class dribl;
}

class dribl : public QMainWindow
{
    Q_OBJECT

public:
    explicit dribl(QWidget *parent = 0);
    ~dribl();

private slots:
    void open();
    void openSniff();

private:
    Ui::dribl *ui;
};

#endif // DRIBL_H
