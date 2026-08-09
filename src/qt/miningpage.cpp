// Copyright (c) 2026 WATTx Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/miningpage.h>
#include <qt/clientmodel.h>
#include <qt/stratumpoolclient.h>
#include <qt/walletmodel.h>
#include <qt/platformstyle.h>
#include <qt/guiutil.h>
#include <qt/addresstablemodel.h>
#include <qt/rpcconsole.h>

#include <interfaces/node.h>
#include <interfaces/wallet.h>
#include <univalue.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <util/time.h>
#include <node/randomx_miner.h>
#include <pow.h>
#include <util/strencodings.h>
#include <streams.h>
#include <consensus/merkle.h>
#include <script/script.h>
#include <key_io.h>
#include <core_io.h>

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QGroupBox>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QSlider>
#include <QComboBox>
#include <QRadioButton>
#include <QCheckBox>
#include <QProgressBar>
#include <QButtonGroup>
#include <QMessageBox>
#include <QRegularExpression>
#include <QThread>
#include <QApplication>
#include <QTextEdit>
#include <QDateTime>

MiningPage::MiningPage(const PlatformStyle *_platformStyle, QWidget *parent)
    : QWidget(parent)
    , clientModel(nullptr)
    , walletModel(nullptr)
    , platformStyle(_platformStyle)
    , currentGpuBandwidth(50)
{
    setupUi();

    // Stats update timer
    statsTimer = new QTimer(this);
    connect(statsTimer, &QTimer::timeout, this, &MiningPage::updateMiningStats);
}

MiningPage::~MiningPage()
{
    if (statsTimer) {
        statsTimer->stop();
    }
    // Stop mining if active
    if (isMining) {
        node::GetRandomXMiner().StopMining();
    }
}

void MiningPage::setupUi()
{
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setSpacing(4);
    mainLayout->setContentsMargins(6, 4, 6, 4);

    // Title (compact)
    QLabel *titleLabel = new QLabel(tr("WATTx Mining (RandomX) - ASIC-resistant, CPU-optimized PoW"), this);
    titleLabel->setStyleSheet("font-weight: bold; font-size: 9pt;");
    titleLabel->setAlignment(Qt::AlignCenter);
    mainLayout->addWidget(titleLabel);

    // === Row 1: Mining Mode + RandomX Settings side by side ===
    QHBoxLayout *row1 = new QHBoxLayout();
    row1->setSpacing(6);

    // Mining mode selection
    QGroupBox *modeGroup = new QGroupBox(tr("Mode"), this);
    QHBoxLayout *modeLayout = new QHBoxLayout(modeGroup);
    modeLayout->setContentsMargins(4, 2, 4, 2);

    soloMiningRadio = new QRadioButton(tr("Solo"), this);
    poolMiningRadio = new QRadioButton(tr("Pool"), this);
    soloMiningRadio->setChecked(true);

    poolMiningRadio->setToolTip(tr("Mine RandomX shares to a stratum pool (XMRig protocol). "
                                   "Rewards are paid by the pool to your selected mining address."));

    QButtonGroup *modeButtonGroup = new QButtonGroup(this);
    modeButtonGroup->addButton(soloMiningRadio);
    modeButtonGroup->addButton(poolMiningRadio);

    modeLayout->addWidget(soloMiningRadio);
    modeLayout->addWidget(poolMiningRadio);
    row1->addWidget(modeGroup);

    connect(soloMiningRadio, &QRadioButton::toggled, this, &MiningPage::onMiningModeChanged);

    // RandomX Settings
    QGroupBox *rxSettingsGroup = new QGroupBox(tr("RandomX"), this);
    QHBoxLayout *rxLayout = new QHBoxLayout(rxSettingsGroup);
    rxLayout->setContentsMargins(4, 2, 4, 2);

    rxModeCombo = new QComboBox(this);
    rxModeCombo->addItem(tr("Light (256MB)"), 0);
    rxModeCombo->addItem(tr("Full (2GB)"), 1);
    rxModeCombo->setCurrentIndex(0);
    rxModeCombo->setToolTip(tr("Full mode uses more memory but mines faster"));

    safeModeCheckbox = new QCheckBox(tr("Safe"), this);
    safeModeCheckbox->setChecked(true);
    safeModeCheckbox->setToolTip(tr("Disable JIT compilation for stability"));

    rxLayout->addWidget(rxModeCombo);
    rxLayout->addWidget(safeModeCheckbox);
    row1->addWidget(rxSettingsGroup, 1);

    mainLayout->addLayout(row1);

    // Not used for RandomX
    shiftSpinBox = nullptr;
    shiftLabel = nullptr;

    // === Row 2: CPU Mining + Mining Address side by side ===
    QHBoxLayout *row2 = new QHBoxLayout();
    row2->setSpacing(6);

    // CPU Mining Controls (compact)
    QGroupBox *cpuGroup = new QGroupBox(tr("CPU Mining"), this);
    QHBoxLayout *cpuLayout = new QHBoxLayout(cpuGroup);
    cpuLayout->setContentsMargins(4, 2, 4, 2);

    enableCpuMining = new QCheckBox(tr("Enable"), this);
    enableCpuMining->setChecked(true);
    cpuLayout->addWidget(enableCpuMining);

    int maxThreads = QThread::idealThreadCount();
    cpuThreadsLabel = new QLabel(tr("Threads:"), this);
    cpuThreadsSpinBox = new QSpinBox(this);
    cpuThreadsSpinBox->setRange(1, maxThreads);
    cpuThreadsSpinBox->setValue(qMax(1, maxThreads - 1));
    cpuThreadsSpinBox->setToolTip(tr("CPU threads (%1 available)").arg(maxThreads));
    cpuThreadsSpinBox->setMaximumWidth(50);

    cpuLayout->addWidget(cpuThreadsLabel);
    cpuLayout->addWidget(cpuThreadsSpinBox);

    cpuCoresAvailableLabel = new QLabel(QString("/%1").arg(maxThreads), this);
    cpuCoresAvailableLabel->setStyleSheet("color: #888;");
    cpuLayout->addWidget(cpuCoresAvailableLabel);
    row2->addWidget(cpuGroup);

    connect(cpuThreadsSpinBox, QOverload<int>::of(&QSpinBox::valueChanged),
            this, &MiningPage::onCpuThreadsChanged);
    connect(enableCpuMining, &QCheckBox::toggled, [this](bool checked) {
        cpuThreadsSpinBox->setEnabled(checked);
    });

    // Mining Address (compact)
    QGroupBox *addressGroup = new QGroupBox(tr("Reward Address"), this);
    QHBoxLayout *addressLayout = new QHBoxLayout(addressGroup);
    addressLayout->setContentsMargins(4, 2, 4, 2);

    miningAddressCombo = new QComboBox(this);
    miningAddressCombo->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    refreshAddressesBtn = new QPushButton(tr("↻"), this);
    refreshAddressesBtn->setMaximumWidth(24);
    refreshAddressesBtn->setToolTip(tr("Refresh addresses"));

    addressLayout->addWidget(miningAddressCombo, 1);
    addressLayout->addWidget(refreshAddressesBtn);
    row2->addWidget(addressGroup, 1);

    connect(refreshAddressesBtn, &QPushButton::clicked, this, &MiningPage::onRefreshAddresses);

    mainLayout->addLayout(row2);

    // Pool Settings (initially hidden)
    poolSettingsGroup = new QGroupBox(tr("Pool Settings"), this);
    createPoolControls(poolSettingsGroup);
    poolSettingsGroup->setVisible(false);
    mainLayout->addWidget(poolSettingsGroup);

    // === Control Button ===
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    miningToggleBtn = new QPushButton(tr("Start Miner"), this);
    miningToggleBtn->setMinimumWidth(120);
    miningToggleBtn->setMinimumHeight(28);
    updateMiningButton(false);
    buttonLayout->addStretch();
    buttonLayout->addWidget(miningToggleBtn);
    buttonLayout->addStretch();
    mainLayout->addLayout(buttonLayout);

    connect(miningToggleBtn, &QPushButton::clicked, this, &MiningPage::onMiningToggleClicked);

    // === Statistics (compact horizontal) ===
    QGroupBox *statsGroup = new QGroupBox(tr("Statistics"), this);
    QGridLayout *statsLayout = new QGridLayout(statsGroup);
    statsLayout->setContentsMargins(4, 2, 4, 4);
    statsLayout->setSpacing(2);

    // Row 0: Status | Hashrate | Uptime
    statsLayout->addWidget(new QLabel(tr("Status:"), this), 0, 0);
    statusLabel = new QLabel(tr("Idle"), this);
    statusLabel->setStyleSheet("font-weight: bold;");
    statsLayout->addWidget(statusLabel, 0, 1);

    statsLayout->addWidget(new QLabel(tr("H/s:"), this), 0, 2);
    hashRateLabel = new QLabel(tr("0"), this);
    statsLayout->addWidget(hashRateLabel, 0, 3);

    statsLayout->addWidget(new QLabel(tr("Uptime:"), this), 0, 4);
    bestMeritLabel = new QLabel("00:00:00", this);
    statsLayout->addWidget(bestMeritLabel, 0, 5);

    // Row 1: Hashes | Accepted | Blocks | Difficulty
    statsLayout->addWidget(new QLabel(tr("Hashes:"), this), 1, 0);
    primesFoundLabel = new QLabel("0", this);
    statsLayout->addWidget(primesFoundLabel, 1, 1);

    statsLayout->addWidget(new QLabel(tr("Accepted:"), this), 1, 2);
    gapsCheckedLabel = new QLabel("0", this);
    statsLayout->addWidget(gapsCheckedLabel, 1, 3);

    statsLayout->addWidget(new QLabel(tr("Blocks:"), this), 1, 4);
    blocksFoundLabel = new QLabel("0", this);
    blocksFoundLabel->setStyleSheet("color: #4CAF50; font-weight: bold;");
    statsLayout->addWidget(blocksFoundLabel, 1, 5);

    // Row 2: Difficulty + Progress bar
    statsLayout->addWidget(new QLabel(tr("Difficulty:"), this), 2, 0);
    currentDifficultyLabel = new QLabel("0", this);
    statsLayout->addWidget(currentDifficultyLabel, 2, 1);

    miningProgressBar = new QProgressBar(this);
    miningProgressBar->setRange(0, 100);
    miningProgressBar->setValue(0);
    miningProgressBar->setTextVisible(false);
    miningProgressBar->setMaximumHeight(8);
    statsLayout->addWidget(miningProgressBar, 2, 2, 1, 4);

    mainLayout->addWidget(statsGroup);

    // === Mining Console (compact) ===
    QGroupBox *consoleGroup = new QGroupBox(tr("Console"), this);
    QVBoxLayout *consoleLayout = new QVBoxLayout(consoleGroup);
    consoleLayout->setContentsMargins(4, 2, 4, 4);
    consoleLayout->setSpacing(2);

    showConsoleCheckbox = new QCheckBox(tr("Show output"), this);
    showConsoleCheckbox->setChecked(true);
    consoleLayout->addWidget(showConsoleCheckbox);

    miningConsole = new QTextEdit(this);
    miningConsole->setReadOnly(true);
    miningConsole->setFont(QFont("Monospace", 7));
    miningConsole->setStyleSheet("QTextEdit { background-color: #1e1e1e; color: #00ff00; font-size: 7pt; }");
    miningConsole->setMinimumHeight(120);
    miningConsole->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    miningConsole->setPlaceholderText(tr("Mining output..."));
    consoleLayout->addWidget(miningConsole, 1);

    mainLayout->addWidget(consoleGroup);

    connect(showConsoleCheckbox, &QCheckBox::toggled, miningConsole, &QTextEdit::setVisible);

    setLayout(mainLayout);
}

void MiningPage::createCpuControls(QGroupBox *group)
{
    // CPU controls are now inlined in setupUi for compact layout
    Q_UNUSED(group);
}

void MiningPage::createGpuControls(QGroupBox *group)
{
    // RandomX doesn't use GPU - this is a stub for compatibility
    QVBoxLayout *layout = new QVBoxLayout(group);

    enableGpuMining = new QCheckBox(tr("GPU Mining (Not available for RandomX)"), this);
    enableGpuMining->setChecked(false);
    enableGpuMining->setEnabled(false);
    enableGpuMining->setToolTip(tr("RandomX is optimized for CPU mining. GPU support is not available."));
    layout->addWidget(enableGpuMining);

    gpuDeviceCombo = new QComboBox(this);
    gpuDeviceCombo->addItem(tr("Not available for RandomX"), -1);
    gpuDeviceCombo->setEnabled(false);
    layout->addWidget(gpuDeviceCombo);

    gpuBandwidthSlider = new QSlider(Qt::Horizontal, this);
    gpuBandwidthSlider->setEnabled(false);
    gpuBandwidthLabel = new QLabel(tr("N/A"), this);
    gpuBandwidthValueLabel = new QLabel("N/A", this);
}

void MiningPage::createPoolControls(QGroupBox *group)
{
    QGridLayout *layout = new QGridLayout(group);

    layout->addWidget(new QLabel(tr("Pool URL:"), this), 0, 0);
    poolUrlEdit = new QLineEdit(this);
    poolUrlEdit->setPlaceholderText(tr("stratum+tcp://pool.example.com:3333"));
    // The public WATTx pool's RandomX port, so pool mining works out of the
    // box. Public ports are 3333-3339; the 34xx range is the pool host's
    // internal numbering and is not reachable from outside.
    poolUrlEdit->setText(QStringLiteral("stratum+tcp://pools.wattxchange.app:3333"));
    layout->addWidget(poolUrlEdit, 0, 1);

    layout->addWidget(new QLabel(tr("Worker Name:"), this), 1, 0);
    poolWorkerEdit = new QLineEdit(this);
    poolWorkerEdit->setPlaceholderText(tr("optional, e.g. rig1"));
    layout->addWidget(poolWorkerEdit, 1, 1);

    layout->addWidget(new QLabel(tr("Password:"), this), 2, 0);
    poolPasswordEdit = new QLineEdit(this);
    poolPasswordEdit->setPlaceholderText(tr("x (usually not required)"));
    poolPasswordEdit->setEchoMode(QLineEdit::Password);
    layout->addWidget(poolPasswordEdit, 2, 1);

    connect(poolUrlEdit, &QLineEdit::textChanged, this, &MiningPage::onPoolUrlChanged);
}

void MiningPage::createStatsDisplay(QGroupBox *group)
{
    // Stats display is now inlined in setupUi for compact layout
    Q_UNUSED(group);
}

void MiningPage::setClientModel(ClientModel *_clientModel)
{
    clientModel = _clientModel;
}

void MiningPage::setWalletModel(WalletModel *_walletModel)
{
    walletModel = _walletModel;
    if (walletModel) {
        updateAddressCombo();
    }
}

void MiningPage::updateAddressCombo()
{
    if (!walletModel) return;

    miningAddressCombo->clear();

    // Get receiving addresses from wallet
    AddressTableModel *addressModel = walletModel->getAddressTableModel();
    if (addressModel) {
        QModelIndex parent;
        for (int i = 0; i < addressModel->rowCount(parent); i++) {
            QModelIndex addressIdx = addressModel->index(i, AddressTableModel::Address, parent);
            QModelIndex labelIdx = addressModel->index(i, AddressTableModel::Label, parent);
            QString address = addressModel->data(addressIdx, Qt::DisplayRole).toString();
            QString label = addressModel->data(labelIdx, Qt::DisplayRole).toString();
            QString type = addressModel->data(addressIdx, AddressTableModel::TypeRole).toString();

            if (type == AddressTableModel::Receive) {
                QString displayText = label.isEmpty() ? address : QString("%1 (%2)").arg(label, address);
                miningAddressCombo->addItem(displayText, address);
            }
        }
    }

    // Add option to generate new address
    miningAddressCombo->addItem(tr("Generate new address..."), "new");
}

void MiningPage::onMiningModeChanged()
{
    bool isPool = poolMiningRadio->isChecked();
    poolSettingsGroup->setVisible(isPool);
}

void MiningPage::onCpuThreadsChanged(int value)
{
    currentCpuThreads = value;

    // If mining is active, log thread change (actual restart happens on next block)
    if (isMining) {
        logToConsole(tr("Thread count changed to %1 - will apply on next block").arg(value));
    }
}

void MiningPage::onGpuBandwidthChanged(int value)
{
    currentGpuBandwidth = value;
    if (gpuBandwidthValueLabel) {
        gpuBandwidthValueLabel->setText(QString("%1%").arg(value));
    }
}

void MiningPage::onRefreshAddresses()
{
    updateAddressCombo();
}

void MiningPage::onPoolUrlChanged()
{
    // Validate pool URL format
    QString url = poolUrlEdit->text();
    if (!url.isEmpty() && !url.startsWith("stratum+tcp://") && !url.startsWith("stratum+ssl://")) {
        poolUrlEdit->setStyleSheet("border: 1px solid orange;");
    } else {
        poolUrlEdit->setStyleSheet("");
    }
}

bool MiningPage::validatePoolSettings()
{
    if (poolMiningRadio->isChecked()) {
        const QString url = poolUrlEdit->text().trimmed();
        if (url.isEmpty()) {
            QMessageBox::warning(this, tr("Mining"), tr("Please enter a pool URL."));
            return false;
        }
        QString hostport = url;
        hostport.remove(QRegularExpression("^stratum\\+(tcp|ssl)://"));
        const int colon = hostport.lastIndexOf(':');
        bool port_ok = false;
        if (colon > 0) hostport.mid(colon + 1).toUShort(&port_ok);
        if (colon <= 0 || !port_ok) {
            QMessageBox::warning(this, tr("Mining"),
                tr("Pool URL must look like stratum+tcp://host:port."));
            return false;
        }
    }
    return true;
}

void MiningPage::onMiningToggleClicked()
{
    if (isMining) {
        stopMining();
    } else {
        if (!validatePoolSettings()) return;

        if (miningAddressCombo->currentData().toString() == "new") {
            // Generate new address
            if (walletModel) {
                QMessageBox::information(this, tr("Mining"),
                    tr("Please generate a new receiving address first from the Receive tab."));
                return;
            }
        }

        startMining();
    }
}

void MiningPage::updateMiningButton(bool mining)
{
    if (mining) {
        miningToggleBtn->setText(tr("Stop Miner"));
        miningToggleBtn->setStyleSheet(
            "QPushButton { "
            "  background-color: #f44336; "
            "  color: white; "
            "  font-weight: bold; "
            "  font-size: 14px; "
            "  padding: 10px 20px; "
            "  border-radius: 5px; "
            "  border: none; "
            "} "
            "QPushButton:hover { background-color: #d32f2f; } "
            "QPushButton:pressed { background-color: #b71c1c; }"
        );
    } else {
        miningToggleBtn->setText(tr("Start Miner"));
        miningToggleBtn->setStyleSheet(
            "QPushButton { "
            "  background-color: #4CAF50; "
            "  color: white; "
            "  font-weight: bold; "
            "  font-size: 14px; "
            "  padding: 10px 20px; "
            "  border-radius: 5px; "
            "  border: none; "
            "} "
            "QPushButton:hover { background-color: #43a047; } "
            "QPushButton:pressed { background-color: #2e7d32; }"
        );
    }
}

void MiningPage::startMining()
{
    if (isMining) return;

    if (!clientModel || !walletModel) {
        statusLabel->setText(tr("Error: Wallet not ready"));
        statusLabel->setStyleSheet("color: #f44336; font-weight: bold;");
        return;
    }

    QString address = miningAddressCombo->currentData().toString();
    if (address.isEmpty() || address == "new") {
        QMessageBox::warning(this, tr("Mining"), tr("Please select a valid mining address."));
        return;
    }

    if (poolMiningRadio->isChecked()) {
        startPoolMining(address);
        return;
    }

    // Clear console and log start
    miningConsole->clear();
    logToConsole(tr("=== WATTx RandomX Mining Started ==="));
    logToConsole(tr("Mining Address: %1").arg(address));

    // Get mining mode and safe mode from UI
    bool fullMode = rxModeCombo && rxModeCombo->currentIndex() == 1;
    int numThreads = cpuThreadsSpinBox->value();
    bool safeMode = safeModeCheckbox && safeModeCheckbox->isChecked();

    // Take the spin box as the source of truth for how many threads to run.
    //
    // currentCpuThreads is initialised to 1 and was only ever updated by the
    // valueChanged signal -- but the spin box's initial setValue() happens in the
    // constructor BEFORE that signal is connected, so the default never reached
    // it. The result: the UI showed "7", the log below printed "Threads: 7", and
    // the miner read currentCpuThreads and ran exactly ONE thread. Anyone who did
    // not happen to nudge the spin box by hand mined at a fraction of their
    // hardware and wondered why they never found a block.
    currentCpuThreads = numThreads;

    logToConsole(tr("Mode: %1, Threads: %2, Safe Mode: %3")
        .arg(fullMode ? "Full (2GB)" : "Light (256MB)")
        .arg(numThreads)
        .arg(safeMode ? "ON" : "OFF"));
    logToConsole(tr(""));

    isMining = true;
    miningStartTime = QDateTime::currentSecsSinceEpoch();  // Track session start
    sessionBlocksFound = 0;
    updateMiningButton(true);  // Show red "Stop Miner" button
    statusLabel->setText(tr("Initializing RandomX..."));
    statusLabel->setStyleSheet("color: #FFA500; font-weight: bold;");

    // Start mining in background thread
    std::thread miningThread([this, address, fullMode, safeMode]() {
        int blocksFound = 0;

        // Initialize RandomX
        QMetaObject::invokeMethod(this, [this]() {
            logToConsole(tr("Initializing RandomX context..."));
        }, Qt::QueuedConnection);

        // Get genesis hash for RandomX initialization via RPC
        std::string rpcResult;
        std::string rpcCommand = "getblockhash 0";
        bool success = RPCConsole::RPCExecuteCommandLine(
            clientModel->node(), rpcResult, rpcCommand, nullptr, walletModel);

        if (!success || rpcResult.empty()) {
            QMetaObject::invokeMethod(this, [this]() {
                logToConsole(tr("Error: Failed to get genesis hash"));
                statusLabel->setText(tr("Error: Failed to initialize"));
                statusLabel->setStyleSheet("color: #f44336; font-weight: bold;");
            }, Qt::QueuedConnection);
            isMining = false;
            return;
        }

        // Parse genesis hash (remove quotes if present)
        std::string genesisHashStr = rpcResult;
        if (genesisHashStr.front() == '"') genesisHashStr = genesisHashStr.substr(1);
        if (genesisHashStr.back() == '"') genesisHashStr.pop_back();

        auto genesisHashOpt = uint256::FromHex(genesisHashStr);
        if (!genesisHashOpt) {
            QMetaObject::invokeMethod(this, [this]() {
                logToConsole(tr("Error: Invalid genesis hash format"));
                statusLabel->setText(tr("Error: Invalid genesis hash"));
                statusLabel->setStyleSheet("color: #f44336; font-weight: bold;");
            }, Qt::QueuedConnection);
            isMining = false;
            return;
        }
        uint256 genesisHash = *genesisHashOpt;

        // Initialize RandomX miner
        node::RandomXMiner& miner = node::GetRandomXMiner();
        auto mode = fullMode ? node::RandomXMiner::Mode::FULL : node::RandomXMiner::Mode::LIGHT;

        QMetaObject::invokeMethod(this, [this, fullMode, safeMode]() {
            logToConsole(tr("Loading RandomX %1 mode%2...")
                .arg(fullMode ? "Full (this may take a minute)" : "Light")
                .arg(safeMode ? " (Safe Mode - JIT disabled)" : ""));
        }, Qt::QueuedConnection);

        if (!miner.Initialize(genesisHash.data(), 32, mode, safeMode)) {
            QMetaObject::invokeMethod(this, [this]() {
                logToConsole(tr("Error: Failed to initialize RandomX"));
                statusLabel->setText(tr("Error: RandomX init failed"));
                statusLabel->setStyleSheet("color: #f44336; font-weight: bold;");
            }, Qt::QueuedConnection);
            isMining = false;
            return;
        }

        QMetaObject::invokeMethod(this, [this]() {
            logToConsole(tr("RandomX initialized successfully!"));
            statusLabel->setText(tr("Mining..."));
            statusLabel->setStyleSheet("color: #4CAF50; font-weight: bold;");
        }, Qt::QueuedConnection);

        // Mining loop - get block template, mine, submit
        while (isMining) {
            try {
                // Get block template via direct RPC call (avoids command line parsing issues)
                UniValue templateRequest(UniValue::VOBJ);
                UniValue rulesArray(UniValue::VARR);
                rulesArray.push_back("segwit");
                templateRequest.pushKV("rules", rulesArray);

                // This page mines RandomX, so the template must be built for
                // RandomX. Without this the node returns a SHA256D template --
                // SHA256D's nBits and no algorithm tag in the version -- and every
                // block we solve is rejected as high-hash: we hash the header with
                // RandomX while consensus, reading the version, hashes it as
                // SHA256D. The two never agree, so the miner runs forever and wins
                // nothing.
                templateRequest.pushKV("algo", "randomx");

                UniValue params(UniValue::VARR);
                params.push_back(templateRequest);

                UniValue templateVal;
                try {
                    templateVal = clientModel->node().executeRpc("getblocktemplate", params, "/");
                } catch (const UniValue& rpcError) {
                    // RPC errors are thrown as UniValue objects (via JSONRPCError)
                    std::string errMsg = rpcError.exists("message") ? rpcError["message"].get_str() : rpcError.write();
                    QMetaObject::invokeMethod(this, [this, errMsg]() {
                        logToConsole(tr("getblocktemplate RPC error: %1").arg(QString::fromStdString(errMsg)));
                    }, Qt::QueuedConnection);
                    std::this_thread::sleep_for(std::chrono::seconds(5));
                    continue;
                } catch (const std::exception& rpcError) {
                    std::string errMsg = rpcError.what();
                    QMetaObject::invokeMethod(this, [this, errMsg]() {
                        logToConsole(tr("getblocktemplate failed: %1").arg(QString::fromStdString(errMsg)));
                    }, Qt::QueuedConnection);
                    std::this_thread::sleep_for(std::chrono::seconds(5));
                    continue;
                }

                if (templateVal.isNull()) {
                    QMetaObject::invokeMethod(this, [this]() {
                        logToConsole(tr("Waiting for block template..."));
                    }, Qt::QueuedConnection);
                    std::this_thread::sleep_for(std::chrono::seconds(5));
                    continue;
                }

                // Extract template data with error checking
                if (templateVal["previousblockhash"].isNull() || templateVal["coinbasevalue"].isNull() ||
                    templateVal["target"].isNull() || templateVal["bits"].isNull() ||
                    templateVal["curtime"].isNull() || templateVal["version"].isNull() ||
                    templateVal["height"].isNull() ||
                    templateVal["hashStateRoot"].isNull() || templateVal["hashUTXORoot"].isNull()) {
                    QMetaObject::invokeMethod(this, [this]() {
                        logToConsole(tr("Error: Block template missing required fields"));
                    }, Qt::QueuedConnection);
                    std::this_thread::sleep_for(std::chrono::seconds(5));
                    continue;
                }

                std::string prevBlockHash = templateVal["previousblockhash"].get_str();
                int64_t coinbaseValue = templateVal["coinbasevalue"].getInt<int64_t>();
                std::string targetStr = templateVal["target"].get_str();
                std::string bitsStr = templateVal["bits"].get_str();
                int32_t curTime = templateVal["curtime"].getInt<int32_t>();
                int32_t version = templateVal["version"].getInt<int32_t>();
                int height = templateVal["height"].getInt<int>();
                std::string hashStateRootStr = templateVal["hashStateRoot"].get_str();
                std::string hashUTXORootStr = templateVal["hashUTXORoot"].get_str();

                QMetaObject::invokeMethod(this, [this, height]() {
                    logToConsole(tr("Got template for height %1").arg(height));
                }, Qt::QueuedConnection);

                // Create coinbase transaction with all outputs from template (including gas refunds)
                CMutableTransaction coinbaseTx;
                coinbaseTx.vin.resize(1);
                coinbaseTx.vin[0].prevout.SetNull();
                coinbaseTx.vin[0].scriptSig = CScript() << height << OP_0;

                // Decode mining address to script
                CTxDestination dest = DecodeDestination(address.toStdString());
                if (!IsValidDestination(dest)) {
                    QMetaObject::invokeMethod(this, [this]() {
                        logToConsole(tr("Error: Invalid mining address"));
                    }, Qt::QueuedConnection);
                    std::this_thread::sleep_for(std::chrono::seconds(5));
                    continue;
                }

                // WATTx: Use coinbaseoutputs from template to include gas refunds
                if (templateVal.exists("coinbaseoutputs") && templateVal["coinbaseoutputs"].isArray()) {
                    const UniValue& outputs = templateVal["coinbaseoutputs"];
                    coinbaseTx.vout.resize(outputs.size());
                    for (size_t i = 0; i < outputs.size(); i++) {
                        const UniValue& out = outputs[i];
                        if (i == 0) {
                            // First output goes to mining address
                            coinbaseTx.vout[0].scriptPubKey = GetScriptForDestination(dest);
                            coinbaseTx.vout[0].nValue = coinbaseValue;
                        } else {
                            // Other outputs (gas refunds) use template values
                            coinbaseTx.vout[i].nValue = out["value"].getInt<int64_t>();
                            std::string scriptHex = out["scriptPubKey"].get_str();
                            std::vector<unsigned char> scriptData = ParseHex(scriptHex);
                            coinbaseTx.vout[i].scriptPubKey = CScript(scriptData.begin(), scriptData.end());
                        }
                    }
                    if (outputs.size() > 1) {
                        QMetaObject::invokeMethod(this, [this, outputs]() {
                            logToConsole(tr("Including %1 gas refund outputs in coinbase").arg(outputs.size() - 1));
                        }, Qt::QueuedConnection);
                    }
                } else {
                    // Fallback: simple coinbase with just mining reward
                    coinbaseTx.vout.resize(1);
                    coinbaseTx.vout[0].scriptPubKey = GetScriptForDestination(dest);
                    coinbaseTx.vout[0].nValue = coinbaseValue;
                }

                // Create block
                CBlock block;
                block.nVersion = version;
                auto prevHashOpt = uint256::FromHex(prevBlockHash);
                if (!prevHashOpt) {
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                    continue;
                }
                block.hashPrevBlock = *prevHashOpt;
                block.nTime = curTime;
                block.nBits = strtoul(bitsStr.c_str(), nullptr, 16);
                block.nNonce = 0;

                // Set Qtum state roots (required for EVM/AAL validation)
                auto stateRootOpt = uint256::FromHex(hashStateRootStr);
                auto utxoRootOpt = uint256::FromHex(hashUTXORootStr);
                if (!stateRootOpt || !utxoRootOpt) {
                    QMetaObject::invokeMethod(this, [this]() {
                        logToConsole(tr("Error: Invalid state root hashes in template"));
                    }, Qt::QueuedConnection);
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                    continue;
                }
                block.hashStateRoot = *stateRootOpt;
                block.hashUTXORoot = *utxoRootOpt;

                // Add coinbase as first transaction
                block.vtx.push_back(MakeTransactionRef(std::move(coinbaseTx)));

                // Add transactions from template
                if (templateVal.exists("transactions") && templateVal["transactions"].isArray()) {
                    const UniValue& txArray = templateVal["transactions"];
                    for (size_t i = 0; i < txArray.size(); i++) {
                        const UniValue& txObj = txArray[i];
                        if (txObj.exists("data") && txObj["data"].isStr()) {
                            std::string txHex = txObj["data"].get_str();
                            CMutableTransaction tx;
                            try {
                                SpanReader{ParseHex(txHex)} >> TX_WITH_WITNESS(tx);
                                block.vtx.push_back(MakeTransactionRef(std::move(tx)));
                            } catch (const std::exception& e) {
                                // Skip invalid transactions
                                LogPrintf("GUI Mining: Failed to parse tx %zu: %s\n", i, e.what());
                            }
                        }
                    }
                    if (txArray.size() > 0) {
                        QMetaObject::invokeMethod(this, [this, txArray]() {
                            logToConsole(tr("Including %1 transactions from mempool").arg(txArray.size()));
                        }, Qt::QueuedConnection);
                    }
                }

                // Calculate merkle root
                block.hashMerkleRoot = BlockMerkleRoot(block);

                // Calculate target
                auto targetOpt = uint256::FromHex(targetStr);
                if (!targetOpt) {
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                    continue;
                }
                uint256 target = *targetOpt;

                QMetaObject::invokeMethod(this, [this, height]() {
                    logToConsole(tr("Mining block at height %1...").arg(height));
                }, Qt::QueuedConnection);

                // Mine using RandomX - read current thread count (may have changed)
                int activeThreads = this->currentCpuThreads.load();
                std::atomic<bool> blockFound{false};
                CBlock foundBlock;
                miner.StartMining(block, target, activeThreads, [&](const CBlock& minedBlock) {
                    foundBlock = minedBlock;  // Copy block first
                    blockFound = true;        // Then signal (memory barrier)
                });

                // Wait for a solution, a new network block, or a stop signal.
                //
                // The template is only valid on top of the tip it was built on. If
                // another block arrives and we keep hashing this one, any solution we
                // find extends a stale parent and is orphaned, so the work is wasted.
                // Nothing else rebuilds it: MineThread holds the block by value and
                // only walks the nonce, and with the full 2^32 range that loop does
                // not end on its own. So watch the tip here and rebuild when it moves.
                const uint256 templateTip = block.hashPrevBlock;
                bool staleTemplate = false;
                int tipPollTicks = 0;
                while (!blockFound && isMining && miner.IsMining()) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));

                    // Poll about once a second; getBestBlockHash() takes cs_main.
                    if (++tipPollTicks >= 10) {
                        tipPollTicks = 0;
                        if (clientModel->node().getBestBlockHash() != templateTip) {
                            staleTemplate = true;
                            break;
                        }
                    }
                }

                if (staleTemplate) {
                    miner.StopMining();
                    QMetaObject::invokeMethod(this, [this]() {
                        logToConsole(tr("New block on the network - rebuilding template"));
                    }, Qt::QueuedConnection);
                }

                if (blockFound && isMining) {
                    QMetaObject::invokeMethod(this, [this]() {
                        logToConsole(tr("Block found! Submitting to network..."));
                    }, Qt::QueuedConnection);

                    // Serialize and submit block
                    DataStream ss{};
                    ss << TX_WITH_WITNESS(foundBlock);
                    std::string blockHex = HexStr(ss);

                    // Submit block via direct RPC call
                    UniValue submitParams(UniValue::VARR);
                    submitParams.push_back(blockHex);

                    try {
                        UniValue submitResult = clientModel->node().executeRpc("submitblock", submitParams, "/");
                        // submitblock returns null on success
                        if (submitResult.isNull()) {
                            blocksFound++;
                            QMetaObject::invokeMethod(this, [this, blocksFound, height]() {
                                sessionBlocksFound++;
                                blocksFoundLabel->setText(QString::number(blocksFound));
                                gapsCheckedLabel->setText(QString::number(sessionBlocksFound));
                                logToConsole(tr("*** BLOCK %1 MINED! ***").arg(height));
                            }, Qt::QueuedConnection);
                            // Wait for chain state to fully update after successful block submission
                            std::this_thread::sleep_for(std::chrono::seconds(2));
                        } else {
                            std::string rejectReason = submitResult.isStr() ? submitResult.get_str() : submitResult.write();
                            QMetaObject::invokeMethod(this, [this, rejectReason]() {
                                logToConsole(tr("Block rejected: %1").arg(QString::fromStdString(rejectReason)));
                            }, Qt::QueuedConnection);
                        }
                    } catch (const UniValue& submitError) {
                        // RPC errors are thrown as UniValue objects (via JSONRPCError)
                        std::string errMsg = submitError.exists("message") ? submitError["message"].get_str() : submitError.write();
                        QMetaObject::invokeMethod(this, [this, errMsg]() {
                            logToConsole(tr("submitblock RPC error: %1").arg(QString::fromStdString(errMsg)));
                        }, Qt::QueuedConnection);
                    } catch (const std::exception& submitError) {
                        std::string errMsg = submitError.what();
                        QMetaObject::invokeMethod(this, [this, errMsg]() {
                            logToConsole(tr("submitblock failed: %1").arg(QString::fromStdString(errMsg)));
                        }, Qt::QueuedConnection);
                    }
                }

                // Small delay before next template
                std::this_thread::sleep_for(std::chrono::milliseconds(100));

            } catch (const UniValue& e) {
                // RPC errors are thrown as UniValue objects (via JSONRPCError)
                std::string errorMsg = e.exists("message") ? e["message"].get_str() : e.write();
                QMetaObject::invokeMethod(this, [this, errorMsg]() {
                    logToConsole(tr("Mining RPC error: %1").arg(QString::fromStdString(errorMsg)));
                }, Qt::QueuedConnection);
                std::this_thread::sleep_for(std::chrono::seconds(5));
            } catch (const std::exception& e) {
                std::string errorMsg = e.what();
                QMetaObject::invokeMethod(this, [this, errorMsg]() {
                    logToConsole(tr("Mining error: %1").arg(QString::fromStdString(errorMsg)));
                }, Qt::QueuedConnection);
                std::this_thread::sleep_for(std::chrono::seconds(5));
            } catch (...) {
                QMetaObject::invokeMethod(this, [this]() {
                    logToConsole(tr("Mining error: unknown exception"));
                }, Qt::QueuedConnection);
                std::this_thread::sleep_for(std::chrono::seconds(5));
            }
        }

        miner.StopMining();

        QMetaObject::invokeMethod(this, [this, blocksFound]() {
            logToConsole(tr("Mining stopped. Total blocks: %1").arg(blocksFound));
        }, Qt::QueuedConnection);
    });
    miningThread.detach();

    // Start stats timer
    statsTimer->start(2000);
}

void MiningPage::startMiningActual()
{
    if (!isMining) return;

    statusLabel->setText(tr("Mining Active - RandomX"));
    statusLabel->setStyleSheet("color: #4CAF50; font-weight: bold;");
    logToConsole(tr("Mining started! Looking for valid hashes..."));

    // Start stats timer
    statsTimer->start(1000);  // Update every 1 second
}

void MiningPage::startPoolMining(const QString& address)
{
    // validatePoolSettings() has already vetted the URL shape.
    QString hostport = poolUrlEdit->text().trimmed();
    hostport.remove(QRegularExpression("^stratum\\+(tcp|ssl)://"));
    const int colon = hostport.lastIndexOf(':');
    const QString host = hostport.left(colon);
    const quint16 port = hostport.mid(colon + 1).toUShort();

    miningConsole->clear();
    logToConsole(tr("=== WATTx Pool Mining (RandomX) ==="));
    logToConsole(tr("Pool: %1:%2").arg(host).arg(port));
    logToConsole(tr("Payout Address: %1").arg(address));

    currentCpuThreads = cpuThreadsSpinBox->value();
    logToConsole(tr("Mode: %1, Threads: %2, Safe Mode: %3")
        .arg(rxModeCombo && rxModeCombo->currentIndex() == 1 ? "Full (2GB)" : "Light (256MB)")
        .arg(currentCpuThreads.load())
        .arg(safeModeCheckbox && safeModeCheckbox->isChecked() ? "ON" : "OFF"));
    logToConsole(tr(""));

    if (!poolClient) {
        poolClient = new StratumPoolClient(this);
        connect(poolClient, &StratumPoolClient::logMessage, this, &MiningPage::logToConsole);
        connect(poolClient, &StratumPoolClient::newJob, this, &MiningPage::handlePoolJob);
        connect(poolClient, &StratumPoolClient::loggedIn, this, [this] {
            statusLabel->setText(tr("Mining Active - Pool (RandomX)"));
            statusLabel->setStyleSheet("color: #4CAF50; font-weight: bold;");
        });
        connect(poolClient, &StratumPoolClient::shareResult, this,
                [this](bool accepted, const QString& error) {
            if (accepted) {
                logToConsole(tr("Share accepted (%1 total)").arg(poolClient->sharesAccepted()));
            } else {
                logToConsole(tr("Share REJECTED: %1 (%2 total)")
                                 .arg(error).arg(poolClient->sharesRejected()));
            }
        });
        connect(poolClient, &StratumPoolClient::disconnected, this,
                [this](const QString& reason) {
            if (!isMining || !poolMode) return;
            if (!poolClient->isActive()) {
                // Login refused: hashing against a pool that will not pay is
                // exactly the silent failure the old fake Pool mode had.
                logToConsole(tr("Pool mining stopped: %1").arg(reason));
                stopMining();
            } else {
                statusLabel->setText(tr("Pool connection lost - reconnecting…"));
                statusLabel->setStyleSheet("color: #FFA500; font-weight: bold;");
            }
        });
    }

    isMining = true;
    poolMode = true;
    miningStartTime = QDateTime::currentSecsSinceEpoch();
    sessionBlocksFound = 0;
    updateMiningButton(true);
    statusLabel->setText(tr("Connecting to pool…"));
    statusLabel->setStyleSheet("color: #FFA500; font-weight: bold;");

    // "ADDRESS.worker" — the pool reads the payout address from the login and
    // the worker tag after the dot.
    QString login = address;
    const QString worker = poolWorkerEdit->text().trimmed();
    if (!worker.isEmpty()) login += QLatin1Char('.') + worker;
    poolClient->start(host, port, login, poolPasswordEdit->text());

    statsTimer->start(1000);
}

void MiningPage::handlePoolJob(const QString& blob_hex, const QString& job_id,
                               const QString& target_hex, const QString& seed_hash, qint64 height)
{
    if (!isMining || !poolMode) return;

    logToConsole(tr("New pool job %1 (parent height %2)").arg(job_id).arg(height));

    const uint64_t gen = ++poolJobGeneration;
    const bool fullMode = rxModeCombo && rxModeCombo->currentIndex() == 1;
    const bool safeMode = safeModeCheckbox && safeModeCheckbox->isChecked();
    const int numThreads = currentCpuThreads.load();
    const std::string blob_str = blob_hex.toStdString();
    const std::string target_str = target_hex.toStdString();
    const std::string seed_str = seed_hash.toStdString();

    // RandomX cache init takes seconds (minutes in FULL mode) — never block the
    // GUI thread. A job thread abandons its work when a newer job supersedes it.
    std::thread jobThread([this, gen, blob_str, target_str, seed_str, job_id,
                           fullMode, safeMode, numThreads]() {
        const auto guiLog = [this](const QString& msg) {
            QMetaObject::invokeMethod(this, [this, msg] { logToConsole(msg); },
                                      Qt::QueuedConnection);
        };

        std::vector<unsigned char> blob = ParseHex(blob_str);

        // Monero-style hashing blob: varint(major) varint(minor)
        // varint(timestamp), 32-byte previous id, then the 4-byte nonce. This
        // is the same walk the pool server does to splice the nonce back in
        // when it verifies the share — the two must agree byte for byte.
        size_t pos = 0;
        for (int i = 0; i < 3 && pos < blob.size(); i++) {
            while (pos < blob.size()) { uint8_t b = blob[pos++]; if (!(b & 0x80)) break; }
        }
        pos += 32;
        if (pos + 4 > blob.size()) {
            guiLog(tr("Pool job blob too short - skipping"));
            return;
        }
        const size_t nonce_offset = pos;

        // Compact stratum target: 16 hex chars are the little-endian u64
        // occupying the top 8 bytes of the 256-bit target (8 chars: top 4).
        const std::vector<unsigned char> target_bytes = ParseHex(target_str);
        uint256 target;
        if (target_bytes.size() == 8) {
            std::memcpy(target.data() + 24, target_bytes.data(), 8);
        } else if (target_bytes.size() == 4) {
            std::memcpy(target.data() + 28, target_bytes.data(), 4);
        } else {
            guiLog(tr("Pool sent an unsupported target format - skipping job"));
            return;
        }

        auto& aux = node::GetRandomXAuxMiner();
        {
            std::lock_guard<std::mutex> lock(poolSeedMutex);
            if (seed_str != poolSeedHash || !aux.IsInitialized()) {
                const std::vector<unsigned char> seed = ParseHex(seed_str);
                if (seed.size() != 32) {
                    guiLog(tr("Pool job carries no usable RandomX seed - skipping"));
                    return;
                }
                guiLog(tr("Initializing RandomX with the pool's seed…"));
                aux.StopMining();
                if (!aux.Initialize(seed.data(), seed.size(),
                                    fullMode ? node::RandomXMiner::Mode::FULL
                                             : node::RandomXMiner::Mode::LIGHT,
                                    safeMode)) {
                    guiLog(tr("RandomX initialization failed - pool mining cannot start"));
                    return;
                }
                poolSeedHash = seed_str;
            }
        }

        if (gen != poolJobGeneration.load()) return;  // a newer job arrived

        aux.StartBlobMining(blob, nonce_offset, target, numThreads,
            [this, job_id](uint32_t nonce, const uint256& hash) {
                const unsigned char nb[4] = {
                    static_cast<unsigned char>(nonce & 0xff),
                    static_cast<unsigned char>((nonce >> 8) & 0xff),
                    static_cast<unsigned char>((nonce >> 16) & 0xff),
                    static_cast<unsigned char>((nonce >> 24) & 0xff),
                };
                const QString nonceHex = QString::fromStdString(
                    HexStr(std::span<const unsigned char>(nb, 4)));
                const QString resultHex = QString::fromStdString(
                    HexStr(std::span<const unsigned char>(hash.begin(), 32)));
                QMetaObject::invokeMethod(this, [this, job_id, nonceHex, resultHex] {
                    if (isMining && poolMode && poolClient) {
                        poolClient->submitShare(job_id, nonceHex, resultHex);
                    }
                }, Qt::QueuedConnection);
            });
    });
    jobThread.detach();
}

void MiningPage::stopMining()
{
    if (!isMining) return;

    logToConsole(tr(""));
    logToConsole(tr("=== Stopping Mining... ==="));

    // Disable button during stop
    miningToggleBtn->setEnabled(false);
    statusLabel->setText(tr("Stopping..."));
    statusLabel->setStyleSheet("color: #FFA500; font-weight: bold;");
    statsTimer->stop();

    const bool pool = poolMode.load();
    if (pool) {
        poolMode = false;
        ++poolJobGeneration;                  // in-flight job threads abandon their work
        if (poolClient) poolClient->stop();   // socket lives on the GUI thread
    }

    // Stop mining in background thread
    std::thread stopThread([this, pool]() {
        if (pool) {
            node::GetRandomXAuxMiner().StopMining();
        } else {
            node::GetRandomXMiner().StopMining();
        }

        QMetaObject::invokeMethod(this, [this]() {
            logToConsole(tr("=== Mining Stopped ==="));
            isMining = false;
            miningToggleBtn->setEnabled(true);
            updateMiningButton(false);  // Show green "Start Miner" button
            statusLabel->setText(tr("Idle"));
            statusLabel->setStyleSheet("font-weight: bold;");
            miningProgressBar->setValue(0);
        }, Qt::QueuedConnection);
    });
    stopThread.detach();
}

void MiningPage::logToConsole(const QString& message)
{
    if (!miningConsole) return;

    QString timestamp = QDateTime::currentDateTime().toString("hh:mm:ss");
    miningConsole->append(QString("[%1] %2").arg(timestamp).arg(message));

    // Auto-scroll to bottom
    QTextCursor cursor = miningConsole->textCursor();
    cursor.movePosition(QTextCursor::End);
    miningConsole->setTextCursor(cursor);
}

void MiningPage::onMiningHashrate(double hashrate, uint64_t totalHashes)
{
    if (!isMining) return;

    // Format hashrate
    QString hrText;
    if (hashrate >= 1000000) {
        hrText = QString("%1 MH/s").arg(hashrate / 1000000.0, 0, 'f', 2);
    } else if (hashrate >= 1000) {
        hrText = QString("%1 KH/s").arg(hashrate / 1000.0, 0, 'f', 2);
    } else {
        hrText = QString("%1 H/s").arg(hashrate, 0, 'f', 1);
    }

    hashRateLabel->setText(hrText);
    primesFoundLabel->setText(QString::number(totalHashes));

    // Update progress bar with animation
    int progress = (totalHashes / 1000) % 100;
    miningProgressBar->setValue(progress);
}

void MiningPage::onBlockFound(const CBlock& block)
{
    logToConsole(tr(""));
    logToConsole(tr("*** VALID BLOCK FOUND! ***"));
    logToConsole(QString("Nonce: %1").arg(block.nNonce));
    logToConsole(QString("Time: %1").arg(block.nTime));
}

void MiningPage::updateMiningStats()
{
    if (!isMining) return;

    // Update hashrate and stats from whichever miner this session runs on:
    // pool mode hashes on the aux context (keyed with the pool's seed), solo
    // on the main one (keyed for WATTx consensus).
    node::RandomXMiner& miner = poolMode ? node::GetRandomXAuxMiner()
                                         : node::GetRandomXMiner();
    double hashrate = miner.GetHashrate();
    uint64_t totalHashes = miner.GetTotalHashes();

    onMiningHashrate(hashrate, totalHashes);

    // Update uptime display
    if (miningStartTime > 0) {
        int64_t uptime = QDateTime::currentSecsSinceEpoch() - miningStartTime;
        int hours = uptime / 3600;
        int minutes = (uptime % 3600) / 60;
        int seconds = uptime % 60;
        bestMeritLabel->setText(QString("%1:%2:%3")
            .arg(hours, 2, 10, QChar('0'))
            .arg(minutes, 2, 10, QChar('0'))
            .arg(seconds, 2, 10, QChar('0')));
    }

    // Update accepted: pool shares in pool mode, blocks found when solo
    if (poolMode && poolClient) {
        gapsCheckedLabel->setText(QString::number(poolClient->sharesAccepted()));
    } else {
        gapsCheckedLabel->setText(QString::number(sessionBlocksFound));
    }

    // Update network difficulty
    if (clientModel) {
        try {
            // Show the difficulty of the block being mined (the "next" one), not the
            // chain tip's: they differ across a retarget, and "next" is what the miner
            // is actually working against. getdifficulty is deliberately not used here
            // because on WATTx it returns an OBJECT (proof-of-work and proof-of-stake
            // retarget separately), so a plain isNum() test never fires and the label
            // would sit on its initial "0" forever.
            UniValue info = clientModel->node().executeRpc("getmininginfo", UniValue(UniValue::VARR), "/");
            double diff = -1.0;
            if (info.isObject()) {
                if (info.exists("next") && info["next"].isObject() &&
                    info["next"].exists("difficulty") && info["next"]["difficulty"].isNum()) {
                    diff = info["next"]["difficulty"].get_real();
                } else if (info.exists("difficulty")) {
                    const UniValue& d = info["difficulty"];
                    if (d.isObject() && d.exists("proof-of-work") && d["proof-of-work"].isNum()) {
                        diff = d["proof-of-work"].get_real();
                    } else if (d.isNum()) {
                        diff = d.get_real();
                    }
                }
            }
            if (diff >= 0.0) {
                if (diff < 0.001) {
                    currentDifficultyLabel->setText(QString::number(diff, 'e', 2));
                } else if (diff < 1.0) {
                    currentDifficultyLabel->setText(QString::number(diff, 'f', 6));
                } else {
                    currentDifficultyLabel->setText(QString::number(diff, 'f', 2));
                }
            }
        } catch (...) {
            // Ignore errors - difficulty display is not critical
        }
    }

    // Log periodic updates
    static uint64_t lastLoggedHashes = 0;
    if (totalHashes - lastLoggedHashes >= 10000) {
        QString hrText;
        if (hashrate >= 1000) {
            hrText = QString("%1 KH/s").arg(hashrate / 1000.0, 0, 'f', 2);
        } else {
            hrText = QString("%1 H/s").arg(hashrate, 0, 'f', 1);
        }
        logToConsole(QString("Hashrate: %1 | Total: %2 hashes").arg(hrText).arg(totalHashes));
        lastLoggedHashes = totalHashes;
    }
}

