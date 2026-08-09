#include <qt/wattxversionchecker.h>

#include <clientversion.h>

#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QUrl>

namespace {
//! "v0.1.7.7" -> QVersionNumber(0,1,7,7). Null when the string is not a plain
//! release tag (a "-g<commit>" or "rc" suffix, or no digits at all).
QVersionNumber ParseReleaseTag(QString tag)
{
    if (tag.startsWith('v')) tag.remove(0, 1);
    int suffix_index = 0;
    QVersionNumber version = QVersionNumber::fromString(tag, &suffix_index);
    if (version.isNull() || suffix_index != tag.length()) return QVersionNumber();
    return version;
}
} // namespace

WattxVersionChecker::WattxVersionChecker(QObject* parent)
    : QObject(parent), m_network(new QNetworkAccessManager(this))
{
    m_current_str = QString::fromStdString(FormatFullVersion());
    m_current = ParseReleaseTag(m_current_str);
}

void WattxVersionChecker::checkForUpdates(bool manual)
{
    QNetworkRequest request(QUrl("https://api.github.com/repos/WATTxChain/WATTx/releases/latest"));
    request.setRawHeader("Accept", "application/vnd.github+json");
    request.setRawHeader("User-Agent", "WATTx-Qt");
#if QT_VERSION >= QT_VERSION_CHECK(5, 15, 0)
    request.setTransferTimeout(30000);
#endif

    QNetworkReply* reply = m_network->get(request);
    connect(reply, &QNetworkReply::finished, this, [this, reply, manual] {
        reply->deleteLater();
        if (reply->error() != QNetworkReply::NoError) {
            Q_EMIT checkFinished(manual, false, false, QString(), QString(), reply->errorString());
            return;
        }

        const QJsonObject release = QJsonDocument::fromJson(reply->readAll()).object();
        const QString tag = release[QStringLiteral("tag_name")].toString();
        QString url = release[QStringLiteral("html_url")].toString();
        if (url.isEmpty()) url = QStringLiteral(WATTX_RELEASES_URL);

        const QVersionNumber latest = ParseReleaseTag(tag);
        if (latest.isNull()) {
            Q_EMIT checkFinished(manual, false, false, tag, url,
                                 tr("could not parse the latest release tag \"%1\"").arg(tag));
            return;
        }

        // A build not made at a release tag has no comparable version.
        const bool update_available = !m_current.isNull() && latest > m_current;
        Q_EMIT checkFinished(manual, true, update_available, tag, url, QString());
    });
}
