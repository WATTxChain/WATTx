// Copyright (c) 2026 WATTx Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WATTX_QT_MININGPAGE_H
#define WATTX_QT_MININGPAGE_H

#include <interfaces/wallet.h>
#include <node/randomx_miner.h>
#include <QWidget>
#include <QTimer>
#include <atomic>
#include <memory>
#include <mutex>
#include <string>

QT_BEGIN_NAMESPACE
class QTextEdit;
QT_END_NAMESPACE

class ClientModel;
class StratumPoolClient;
class WalletModel;
class PlatformStyle;

QT_BEGIN_NAMESPACE
class QComboBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QSpinBox;
class QSlider;
class QGroupBox;
class QRadioButton;
class QCheckBox;
class QProgressBar;
QT_END_NAMESPACE

/**
 * Mining page widget with CPU/GPU mining controls,
 * pool configuration, and mining statistics.
 */
class MiningPage : public QWidget
{
    Q_OBJECT

public:
    explicit MiningPage(const PlatformStyle *platformStyle, QWidget *parent = nullptr);
    ~MiningPage();

    void setClientModel(ClientModel *clientModel);
    void setWalletModel(WalletModel *walletModel);

public Q_SLOTS:
    void updateMiningStats();

private Q_SLOTS:
    void onMiningToggleClicked();
    void onMiningModeChanged();
    void onCpuThreadsChanged(int value);
    void onGpuBandwidthChanged(int value);
    void onRefreshAddresses();
    void onPoolUrlChanged();

private:
    void setupUi();
    void createCpuControls(QGroupBox *group);
    void createGpuControls(QGroupBox *group);
    void createPoolControls(QGroupBox *group);
    void createStatsDisplay(QGroupBox *group);
    void updateAddressCombo();
    void startMining();
    void startMiningActual();  // Called after GPU initialization (async)
    void startPoolMining(const QString& address);
    void handlePoolJob(const QString& blob_hex, const QString& job_id,
                       const QString& target_hex, const QString& seed_hash, qint64 height);
    void stopMining();
    bool validatePoolSettings();

    ClientModel *clientModel;
    WalletModel *walletModel;
    const PlatformStyle *platformStyle;

    // Mining mode
    QRadioButton *soloMiningRadio;
    QRadioButton *poolMiningRadio;

    // CPU controls
    QCheckBox *enableCpuMining;
    QSpinBox *cpuThreadsSpinBox;
    QLabel *cpuThreadsLabel;
    QLabel *cpuCoresAvailableLabel;

    // GPU controls
    QCheckBox *enableGpuMining;
    QComboBox *gpuDeviceCombo;
    QSlider *gpuBandwidthSlider;
    QLabel *gpuBandwidthLabel;
    QLabel *gpuBandwidthValueLabel;

    // Mining address
    QComboBox *miningAddressCombo;
    QPushButton *refreshAddressesBtn;

    // Pool settings
    QGroupBox *poolSettingsGroup;
    QLineEdit *poolUrlEdit;
    QLineEdit *poolWorkerEdit;
    QLineEdit *poolPasswordEdit;

    // Mining difficulty/shift
    QSpinBox *shiftSpinBox;
    QLabel *shiftLabel;

    // RandomX mode selection
    QComboBox *rxModeCombo;

    // Safe mode checkbox (disables JIT to prevent crashes)
    QCheckBox *safeModeCheckbox;

    // Control button (single toggle button)
    QPushButton *miningToggleBtn;

    // Statistics display
    QLabel *statusLabel;
    QLabel *hashRateLabel;
    QLabel *primesFoundLabel;
    QLabel *gapsCheckedLabel;
    QLabel *blocksFoundLabel;
    QLabel *bestMeritLabel;
    QLabel *currentDifficultyLabel;
    QProgressBar *miningProgressBar;

    // Timer for stats updates
    QTimer *statsTimer;

    // Mining state
    std::atomic<bool> isMining{false};
    std::atomic<int> currentCpuThreads{1};

    // Pool mining state. The stratum client lives on the GUI thread; pool jobs
    // are prepared (seed init + blob mining start) on detached worker threads,
    // serialized loosely by poolJobGeneration — a job thread abandons its work
    // when a newer job has arrived. poolSeedMutex guards poolSeedHash, which
    // tracks the seed the AUX RandomX context is currently keyed with.
    StratumPoolClient *poolClient{nullptr};
    std::atomic<bool> poolMode{false};
    std::atomic<uint64_t> poolJobGeneration{0};
    std::mutex poolSeedMutex;
    std::string poolSeedHash;
    int currentGpuBandwidth;
    int64_t miningStartTime{0};  // For uptime tracking
    int sessionBlocksFound{0};   // Blocks found this session

    // Mining console output
    QTextEdit *miningConsole;
    QCheckBox *showConsoleCheckbox;

    // Console logging
    void logToConsole(const QString& message);
    void onMiningHashrate(double hashrate, uint64_t totalHashes);
    void onBlockFound(const CBlock& block);
    void updateMiningButton(bool mining);
};

#endif // WATTX_QT_MININGPAGE_H
