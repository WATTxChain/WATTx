#ifndef BITCOIN_QT_WATTXVERSIONCHECKER_H
#define BITCOIN_QT_WATTXVERSIONCHECKER_H

#include <QObject>
#include <QString>
#include <QVersionNumber>

class QNetworkAccessManager;

#define WATTX_RELEASES_URL "https://github.com/WATTxChain/WATTx/releases"

/** Asks GitHub for the newest WATTx release and compares it against the
 *  running build. Asynchronous: call checkForUpdates() and listen on
 *  checkFinished(); nothing blocks the GUI thread.
 *
 *  The running version comes from FormatFullVersion(), which is the git tag
 *  the build was made at. Release binaries are built at a release tag
 *  (vMAJ.MIN.REV.BUILD) and compare normally; a build made anywhere else
 *  (development, CI) has no comparable version and never reports an update.
 */
class WattxVersionChecker : public QObject
{
    Q_OBJECT
public:
    explicit WattxVersionChecker(QObject* parent = nullptr);

    //! Version string of the running build, e.g. "v0.1.7.7".
    QString currentVersion() const { return m_current_str; }
    //! True when the running build was made at a release tag and can be compared.
    bool isReleaseBuild() const { return !m_current.isNull(); }
    //! False when this build's Qt has no HTTP support (the static release Qt is
    //! built -no-feature-http -no-openssl). checkForUpdates() then reports an
    //! unsupported check and the UI should offer the releases page instead.
    bool supported() const;

    //! Query GitHub for the newest release. manual=true for a user-triggered
    //! check (the caller then reports errors and "up to date" too).
    void checkForUpdates(bool manual);

Q_SIGNALS:
    //! ok=false means the check itself failed (network or parse); error says why.
    void checkFinished(bool manual, bool ok, bool update_available,
                       QString latest_version, QString release_url, QString error);

private:
    QNetworkAccessManager* m_network;
    QString m_current_str;
    QVersionNumber m_current;
};

#endif // BITCOIN_QT_WATTXVERSIONCHECKER_H
