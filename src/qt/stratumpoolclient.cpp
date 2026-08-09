#include <qt/stratumpoolclient.h>

#include <clientversion.h>

#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QTcpSocket>

StratumPoolClient::StratumPoolClient(QObject* parent)
    : QObject(parent), m_socket(new QTcpSocket(this))
{
    connect(m_socket, &QTcpSocket::connected, this, &StratumPoolClient::onConnected);
    connect(m_socket, &QTcpSocket::readyRead, this, &StratumPoolClient::onReadyRead);
#if QT_VERSION >= QT_VERSION_CHECK(5, 15, 0)
    connect(m_socket, &QTcpSocket::errorOccurred, this, &StratumPoolClient::onSocketError);
#else
    connect(m_socket, QOverload<QAbstractSocket::SocketError>::of(&QAbstractSocket::error),
            this, &StratumPoolClient::onSocketError);
#endif
    connect(m_socket, &QTcpSocket::disconnected, this, [this] {
        m_logged_in = false;
        m_keepalive_timer.stop();
        if (m_active) {
            Q_EMIT disconnected(tr("connection closed by pool"));
            scheduleReconnect();
        }
    });

    m_keepalive_timer.setInterval(60 * 1000);
    connect(&m_keepalive_timer, &QTimer::timeout, this, [this] {
        if (m_logged_in) {
            m_socket->write(QStringLiteral("{\"id\":%1,\"jsonrpc\":\"2.0\",\"method\":\"keepalived\",\"params\":{}}\n")
                                .arg(m_next_request_id++).toUtf8());
        }
    });

    m_reconnect_timer.setSingleShot(true);
    connect(&m_reconnect_timer, &QTimer::timeout, this, [this] {
        if (m_active) {
            Q_EMIT logMessage(tr("Reconnecting to %1:%2…").arg(m_host).arg(m_port));
            m_socket->connectToHost(m_host, m_port);
        }
    });
}

void StratumPoolClient::start(const QString& host, quint16 port, const QString& login, const QString& password)
{
    stop();
    m_host = host;
    m_port = port;
    m_login = login;
    m_password = password.isEmpty() ? QStringLiteral("x") : password;
    m_active = true;
    m_reconnect_delay_ms = 2000;
    m_shares_accepted = 0;
    m_shares_rejected = 0;
    Q_EMIT logMessage(tr("Connecting to pool %1:%2…").arg(host).arg(port));
    m_socket->connectToHost(host, port);
}

void StratumPoolClient::stop()
{
    m_active = false;
    m_logged_in = false;
    m_keepalive_timer.stop();
    m_reconnect_timer.stop();
    m_read_buffer.clear();
    if (m_socket->state() != QAbstractSocket::UnconnectedState) {
        m_socket->abort();
    }
}

void StratumPoolClient::onConnected()
{
    m_reconnect_delay_ms = 2000;
    m_read_buffer.clear();

    // XMRig object-form login. The agent string identifies the wallet in the
    // pool's logs; algo declares what this miner can hash.
    QJsonObject params{
        {QStringLiteral("login"), m_login},
        {QStringLiteral("pass"), m_password},
        {QStringLiteral("agent"),
         QStringLiteral("wattx-qt/%1").arg(QString::fromStdString(FormatFullVersion()))},
    };
    QJsonObject msg{
        {QStringLiteral("id"), 1},
        {QStringLiteral("jsonrpc"), QStringLiteral("2.0")},
        {QStringLiteral("method"), QStringLiteral("login")},
        {QStringLiteral("params"), params},
    };
    m_socket->write(QJsonDocument(msg).toJson(QJsonDocument::Compact) + "\n");
    Q_EMIT logMessage(tr("Connected — logging in as %1").arg(m_login));
}

void StratumPoolClient::onReadyRead()
{
    m_read_buffer += m_socket->readAll();
    int newline;
    while ((newline = m_read_buffer.indexOf('\n')) >= 0) {
        const QByteArray line = m_read_buffer.left(newline);
        m_read_buffer.remove(0, newline + 1);
        if (!line.trimmed().isEmpty()) handleLine(line);
    }
    // A server that never terminates its line is not speaking this protocol.
    if (m_read_buffer.size() > 1 << 20) {
        Q_EMIT logMessage(tr("Pool sent oversized message — disconnecting"));
        m_socket->abort();
    }
}

void StratumPoolClient::handleLine(const QByteArray& line)
{
    const QJsonObject msg = QJsonDocument::fromJson(line).object();
    if (msg.isEmpty()) return;

    // Job push
    if (msg[QStringLiteral("method")].toString() == QLatin1String("job")) {
        handleJobObject(msg[QStringLiteral("params")].toObject());
        return;
    }

    const qint64 id = msg[QStringLiteral("id")].toVariant().toLongLong();
    const QJsonObject error = msg[QStringLiteral("error")].toObject();
    const QJsonObject result = msg[QStringLiteral("result")].toObject();

    if (id == 1) {
        // Login response
        if (!error.isEmpty()) {
            const QString reason = error[QStringLiteral("message")].toString();
            Q_EMIT logMessage(tr("Pool refused login: %1").arg(reason));
            m_active = false;  // credentials are wrong; retrying won't help
            m_socket->abort();
            Q_EMIT disconnected(tr("login refused: %1").arg(reason));
            return;
        }
        m_logged_in = true;
        m_keepalive_timer.start();
        Q_EMIT loggedIn();
        const QJsonObject job = result[QStringLiteral("job")].toObject();
        if (!job.isEmpty()) handleJobObject(job);
        return;
    }

    if (id >= 2) {
        // Submit (or keepalive) response. Keepalive replies carry status too;
        // only count messages that answer a share when they say OK/error.
        if (!error.isEmpty()) {
            m_shares_rejected++;
            Q_EMIT shareResult(false, error[QStringLiteral("message")].toString());
        } else if (result[QStringLiteral("status")].toString() == QLatin1String("OK")) {
            // Keepalive answers are {"status":"KEEPALIVED"} on most pools and
            // never "OK"; treat every OK as an accepted share.
            m_shares_accepted++;
            Q_EMIT shareResult(true, QString());
        }
    }
}

void StratumPoolClient::handleJobObject(const QJsonObject& job)
{
    const QString blob = job[QStringLiteral("blob")].toString();
    const QString job_id = job[QStringLiteral("job_id")].toString();
    const QString target = job[QStringLiteral("target")].toString();
    const QString seed = job[QStringLiteral("seed_hash")].toString();
    const qint64 height = job[QStringLiteral("height")].toVariant().toLongLong();
    if (blob.isEmpty() || job_id.isEmpty() || target.isEmpty()) {
        Q_EMIT logMessage(tr("Pool sent malformed job — ignoring"));
        return;
    }
    Q_EMIT newJob(blob, job_id, target, seed, height);
}

void StratumPoolClient::submitShare(const QString& job_id, const QString& nonce_hex, const QString& result_hex)
{
    if (!m_logged_in) return;
    // ARRAY params [job_id, nonce, result] — the form the server parses.
    QString msg = QStringLiteral("{\"id\":%1,\"jsonrpc\":\"2.0\",\"method\":\"submit\","
                                 "\"params\":[\"%2\",\"%3\",\"%4\"]}\n")
                      .arg(m_next_request_id++)
                      .arg(job_id, nonce_hex, result_hex);
    m_socket->write(msg.toUtf8());
}

void StratumPoolClient::onSocketError()
{
    if (!m_active) return;
    m_logged_in = false;
    m_keepalive_timer.stop();
    Q_EMIT disconnected(m_socket->errorString());
    scheduleReconnect();
}

void StratumPoolClient::scheduleReconnect()
{
    if (!m_active || m_reconnect_timer.isActive()) return;
    Q_EMIT logMessage(tr("Connection lost (%1) — retrying in %2 s")
                          .arg(m_socket->errorString())
                          .arg(m_reconnect_delay_ms / 1000));
    m_reconnect_timer.start(m_reconnect_delay_ms);
    m_reconnect_delay_ms = std::min(m_reconnect_delay_ms * 2, 60000);
}
