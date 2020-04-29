#include "server.h"
#include <qdatastream.h>
#include <QTcpSocket>
#include <QFile>
#include "Logger.h"
#include <qlist.h>




Logger *logger = nullptr;
QDataStream::Version kDSVersion = QDataStream::Qt_5_5;
QList<QSslSocket> list;



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

    if(command == "getLists")
    {
        logger->log("Getting new lists");

    }else if(command == "sendLists")
    {
        logger->log("Sending lists");


    }





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






