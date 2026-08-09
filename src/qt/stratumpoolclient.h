#ifndef BITCOIN_QT_STRATUMPOOLCLIENT_H
#define BITCOIN_QT_STRATUMPOOLCLIENT_H

#include <QObject>
#include <QString>
#include <QTimer>

class QTcpSocket;

/** XMRig-protocol (Monero-style JSON-RPC line) stratum client for pool
 *  mining from the wallet. Speaks the protocol the WATTx merged stratum
 *  serves on its RandomX port:
 *
 *    -> {"id":1,"method":"login","params":{"login":ADDR,"pass":..,"agent":..}}
 *    <- {"id":1,"result":{"id":SESSION,"job":{blob,job_id,target,seed_hash,..}}}
 *    <- {"method":"job","params":{blob,job_id,target,seed_hash,..}}   (pushes)
 *    -> {"id":N,"method":"submit","params":[job_id,nonce_hex,result_hex]}
 *    <- {"id":N,"result":{"status":"OK"}} | {"id":N,"error":{...}}
 *
 *  Submit params are sent in ARRAY form — that is what the server parses.
 *  Purely asynchronous; owns a keepalive timer and reconnects with backoff.
 */
class StratumPoolClient : public QObject
{
    Q_OBJECT
public:
    explicit StratumPoolClient(QObject* parent = nullptr);

    //! Connect and log in. login is "WTXADDR" or "WTXADDR.worker".
    void start(const QString& host, quint16 port, const QString& login, const QString& password);
    //! Disconnect and stop reconnecting.
    void stop();

    bool isLoggedIn() const { return m_logged_in; }
    //! False once stop()ped or the pool refused the login (no reconnect coming).
    bool isActive() const { return m_active; }
    quint64 sharesAccepted() const { return m_shares_accepted; }
    quint64 sharesRejected() const { return m_shares_rejected; }

public Q_SLOTS:
    //! nonce_hex: the 4 blob bytes as hex; result_hex: the 32-byte PoW hash as hex.
    void submitShare(const QString& job_id, const QString& nonce_hex, const QString& result_hex);

Q_SIGNALS:
    void loggedIn();
    void disconnected(const QString& reason);
    //! A job to mine (from the login response or a "job" push).
    void newJob(const QString& blob_hex, const QString& job_id, const QString& target_hex,
                const QString& seed_hash, qint64 height);
    void shareResult(bool accepted, const QString& error);
    void logMessage(const QString& message);

private Q_SLOTS:
    void onConnected();
    void onReadyRead();
    void onSocketError();

private:
    void handleLine(const QByteArray& line);
    void handleJobObject(const class QJsonObject& job);
    void scheduleReconnect();

    QTcpSocket* m_socket;
    QTimer m_keepalive_timer;
    QTimer m_reconnect_timer;

    QString m_host;
    quint16 m_port{0};
    QString m_login;
    QString m_password;

    bool m_active{false};        // start()ed and not stop()ped
    bool m_logged_in{false};
    int m_reconnect_delay_ms{2000};
    qint64 m_next_request_id{2}; // 1 is the login
    QByteArray m_read_buffer;

    quint64 m_shares_accepted{0};
    quint64 m_shares_rejected{0};
};

#endif // BITCOIN_QT_STRATUMPOOLCLIENT_H
