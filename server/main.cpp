#include <QCoreApplication>
#include <QDebug>
#include <qcommandlineparser.h>
#include "server.h"

/*

Create a cert
https://stackoverflow.com/questions/33198360/qt-with-qsslsocket-not-connecting-properly

#Step 1: Generate a Private Key
openssl genrsa -des3 -out server.key 1024

#Step 2: Generate a CSR (Certificate Signing Request)
#Common Name (eg, your name or your server's hostname) []:example.com
openssl req -new -key server.key -out server.csr

#Step 3: Remove Passphrase from Key
cp server.key server.key.org
openssl rsa -in server.key.org -out server.key

#Step 4: Generating a Self-Signed Certificate
openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt


Test the connection
openssl s_client -connect 127.0.0.1:2020

open a web browser and navigate to 127.0.0.1:2020

 */
int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);
    QCoreApplication::setApplicationName("computerControllerServer");
    QCoreApplication::setApplicationVersion("0.1");
    QCommandLineParser parser;
    parser.setApplicationDescription("Application for keeping track of videos and what episode you are up to.");
    parser.addHelpOption();
    parser.addVersionOption();

    QCommandLineOption portOption(QStringList() << "p" << "port", QCoreApplication::translate("main", "Start server on specified port"),QCoreApplication::translate("main", "port"));
        parser.addOption(portOption);

        parser.process(a);
        const QStringList args = parser.positionalArguments();
        qint16 port = 2020;
        if(parser.isSet(portOption))
        {
            port = parser.value(portOption).toUShort();
            if(port == 0 )
            {
                qInfo() << "Error please enter a valid port";
                exit(EXIT_SUCCESS);
            }
        }

    Server server;
    server.setKey("server.key");
    server.setCert("server.crt");

    if(!server.listen(QHostAddress::Any, port))
    {
        qInfo() << server.errorString();
    }
    else
    {
        qInfo() << "Listening on " << server.serverAddress() << ":" << server.serverPort();
    }

    return a.exec();
}
