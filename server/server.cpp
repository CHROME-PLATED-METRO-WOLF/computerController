#include "server.h"
#include <qdatastream.h>
#include <QTcpSocket>
#include <QFile>
#include "Logger.h"
#include <qlist.h>




Logger *logger = nullptr;
QDataStream::Version kDSVersion = QDataStream::Qt_5_5;
QList<QSslSocket> controllers;
QList<QSslSocket> slaves;



Server::Server(QObject *parent) : QTcpServer(parent)
{

    logger = new Logger("lastlog.txt", 3);

}

Server::~Server()
{
}

void Server::setCert(QString value)
{
    certPath = value;
}

void Server::setKey(QString value)
{
    keyPath = value;
}


void Server::disconnected()
{
    QSslSocket* socket = qobject_cast<QSslSocket*>(sender());
    qInfo() << "Disconnected" << socket;
    socket->deleteLater();
}



void Server::readyRead()
{

    //when client connects server should send a command to authenticate who the client is
    //if the client doesnt send back a responce in x time then disconnect the user
    //if they send invalid data aka not an actual client connecting then disconnect them straight away
    //if they authenticate either add them to the slave list or controller list, note anyone can be a
    //slave without authenticating (with user and pass) but controllers must be verified
    //also whenever a command is sent to the slaves all the controllers need to get updated with the
    //status of the slaves
    logger->log( "Ready read");
    QSslSocket* socket = qobject_cast<QSslSocket*>(sender());

    QString command;

    typedef quint32 QBALength;
    if (socket->bytesAvailable() < sizeof(QBALength)) return;
    auto buff = socket->peek(sizeof(QBALength));
    QDataStream sds(&buff, QIODevice::ReadOnly);
    // We use a documented implementation detail:
    // See http://doc.qt.io/qt-5/datastreamformat.html
    // A QByteArray is serialized as a quint32 size followed by raw data.
    QBALength size;
    sds >> size;
    logger->log("expected size of data: " + QString::number(size));
            if (size == 0xFFFFFFFF) {
        // null QByteArray, discard
        socket->read(sizeof(QBALength));
        return;
    }



    if (socket->bytesAvailable() < size)  return;
    QByteArray buf;
    QDataStream bds(socket);
    bds.setVersion(kDSVersion);
    bds >> buf;
    QDataStream ds(&buf, QIODevice::ReadOnly);
    ds.setVersion(kDSVersion);
    ds >> command;
    logger->log("Command: " + command);

    if(command == "Auth")
    {
        logger->log("Client trying to authenticate");
        logger->log("Checking if allready authed");
        if(checkIfSocketIsAuth(*socket) == true)
        {
            logger->log("ERROR client is allready authed");
            //do something either disconnect or send message back
            //this shouldnt happen
        }else
        {
            logger->log("Authenticating");

        }

    }else if(command == "sendLists")
    {
        logger->log("Sending lists");


    }



}

bool Server::checkIfSocketIsAuth(QSslSocket &sock)
{
    bool slaveStatus = false;
    bool controllerStatus = false;
    for(int i = 0; i < slaves.size(); i++)
    {
        if(slaves.contains(sock))
        {
            slaveStatus = true;
        }
    }

    for(int i = 0; i < controllers.size(); i++)
    {
        if(controllers.contains(sock))
        {
            controllerStatus = true;
        }
    }

    if(slaveStatus == true && controllerStatus == true)
    {
        //we have a problem
        logger->log("ERROR This socket is in both lists THATS A PROBLEM");
        sock.close();
        slaves.removeAll(sock);
        controllers.removeAll(sock);
        return false;
    }else if(slaveStatus == true || controllerStatus == true)
    {
        return true;
    }

    return false;

}

void Server::sendAuthMessage()
{
logger->log("Sending auth message");
QSslSocket* socket = qobject_cast<QSslSocket*>(sender());
QByteArray Data;
QDataStream sds(socket);
QDataStream bds(&Data, QIODevice::WriteOnly);
sds.setVersion(kDSVersion);
bds.setVersion(kDSVersion);
QString command = "Auth";
bds << command;
sds << Data;

}




void Server::encrypted()
{
    QSslSocket* socket = qobject_cast<QSslSocket*>(sender());
    logger->log( "Encrypted" + socket->peerAddress().toString());
}

void Server::encryptedBytesWritten(qint64 written)
{
    QSslSocket* socket = qobject_cast<QSslSocket*>(sender());
    logger->log( QString::number(written) + " encryptedBytesWritten to: " + socket->peerAddress().toString() + ":" + QString::number(socket->peerPort()));
}

void Server::modeChanged(QSslSocket::SslMode mode)
{
    QSslSocket* socket = qobject_cast<QSslSocket*>(sender());
    logger->log( "modeChanged" + socket->peerAddress().toString() + ":" + QString::number(socket->peerPort()) + QString(mode));
}

void Server::peerVerifyError(const QSslError &error)
{
    QSslSocket* socket = qobject_cast<QSslSocket*>(sender());
    logger->log( "peerVerifyError" + socket->peerAddress().toString() + ":" + QString::number(socket->peerPort()));
}

void Server::sslErrors(const QList<QSslError> &errors)
{
    QSslSocket* socket = qobject_cast<QSslSocket*>(sender());
    logger->log( "sslErrors" + socket->peerAddress().toString() + ":" + QString::number(socket->peerPort()));
    socket->ignoreSslErrors(errors);
}

void Server::socketError(QAbstractSocket::SocketError err)
{
    QMetaEnum metaEnum = QMetaEnum::fromType<QAbstractSocket::SocketError>();
    QSslSocket* socket = qobject_cast<QSslSocket*>(sender());
    logger->log( "socketError: " + socket->peerAddress().toString() + ":" + QString::number(socket->peerPort()) + QString(metaEnum.valueToKey(err)));
}

void Server::incomingConnection(qintptr handle)
{
    logger->log( "incomming connection " + QString::number(handle));
    QSslSocket* socket = new QSslSocket(this);

    connect(socket,&QSslSocket::disconnected,this,&Server::disconnected);
    connect(socket,&QSslSocket::readyRead,this,&Server::readyRead);

    connect(socket,&QSslSocket::encrypted,this,&Server::encrypted);
    connect(socket,&QSslSocket::encryptedBytesWritten,this,&Server::encryptedBytesWritten);
    connect(socket,&QSslSocket::modeChanged,this,&Server::modeChanged);
    connect(socket,&QSslSocket::peerVerifyError,this,&Server::peerVerifyError);
    connect(socket,QOverload<const QList<QSslError> &>::of(&QSslSocket::sslErrors),this,&Server::sslErrors);
    connect(socket,QOverload<QAbstractSocket::SocketError>::of(&QAbstractSocket::error),this, &Server::socketError);

    logger->log( "Connected " + socket->peerAddress().toString() + ":" + QString::number(socket->peerPort()));
    socket->setSocketDescriptor(handle);
    socket->setLocalCertificate(certPath,QSsl::Pem);
    socket->setPrivateKey(keyPath, QSsl::Rsa, QSsl::Pem);
    socket->setPeerVerifyMode(QSslSocket::VerifyNone);
    socket->setProtocol(QSsl::TlsV1SslV3);

    socket->startServerEncryption();


}






