from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QScrollArea,
    QFrame, QSizePolicy, QSpacerItem
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont

from ..page import Page
from src.tweaks.tweak_loader import load_6g_advanced, load_cellular
from src.tweaks.tweaks import TweakID


class SixGPage(Page, QWidget):
    """6G & advanced cellular managed-preference keys.
    Targets com.apple.coretelephony — read by CommCenter and CoreTelephony.
    Applied via the original sparserestore path."""

    def __init__(self):
        Page.__init__(self)
        QWidget.__init__(self)
        self._setup_ui()

    def _setup_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        outer.addWidget(scroll)

        container = QWidget()
        self.layout_main = QVBoxLayout(container)
        self.layout_main.setContentsMargins(30, 20, 30, 20)
        self.layout_main.setSpacing(12)
        scroll.setWidget(container)

        title_font = QFont()
        title_font.setPointSize(18)
        title_font.setBold(True)
        section_font = QFont()
        section_font.setPointSize(11)
        section_font.setBold(True)

        title = QLabel("6G & Advanced Cellular")
        title.setFont(title_font)
        self.layout_main.addWidget(title)

        subtitle = QLabel(
            "Advanced com.apple.coretelephony managed-preference keys for "
            "5G/6G radio features, carrier aggregation, MIMO, and low-latency "
            "network slicing. Applied via sparserestore — the original method."
        )
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet("color: #aaaaaa; font-size: 13px;")
        self.layout_main.addWidget(subtitle)

        # ── 6G (IMT-2030) ──────────────────────────────────────────────────────
        self._add_divider()
        self._section("6G  (IMT-2030 / Next-Generation Radio)", section_font)

        self.cell6GBtns = self._add_row(
            "6G Radio  [6GEnabled]",
            "6GEnabled — gates the modem's 6G NR capability. 6G (IMT-2030) "
            "targets sub-terahertz bands for >1 Tbps peak throughput and "
            "<0.1 ms air-interface latency. Future-hardware key."
        )

        # ── 5G Advanced ─────────────────────────────────────────────────────────
        self._add_divider()
        self._section("5G Advanced (3GPP Release 18 +)", section_font)

        self.mmWaveBtns = self._add_row(
            "mmWave (FR2) Radio  [mmWaveEnabled]",
            "mmWaveEnabled — allows the modem to connect on millimetre-wave "
            "5G NR bands (24–100 GHz). Supported on iPhone 12 US and later "
            "US/Japan/Korea models with the mmWave antenna window."
        )
        self.saBtns = self._add_row(
            "5G Standalone Mode  [Standalone5GEnabled]",
            "Standalone5GEnabled — uses the 5G NR core network (5GC) instead "
            "of anchoring to an LTE core. SA removes LTE fallback latency and "
            "enables network slicing and full 5G QoS."
        )
        self.nrDCBtns = self._add_row(
            "NR Dual Connectivity  [NRDualConnectivityEnabled]",
            "NRDualConnectivityEnabled — bonds a primary NR cell with a secondary "
            "NR cell (NR-DC / EN-DC) for combined throughput across two carriers "
            "simultaneously."
        )

        # ── Radio Efficiency ────────────────────────────────────────────────────
        self._add_divider()
        self._section("Radio Efficiency & Throughput", section_font)

        self.carrierAggBtns = self._add_row(
            "Carrier Aggregation  [CarrierAggregationEnabled]",
            "CarrierAggregationEnabled — bonds up to 5 LTE or NR component "
            "carriers across different frequency bands into a single logical "
            "channel for higher peak bitrates."
        )
        self.mimoBtns = self._add_row(
            "Advanced MIMO  [AdvancedMIMOEnabled]",
            "AdvancedMIMOEnabled — enables massive MIMO spatial multiplexing "
            "and beam-forming on supported antenna arrays, increasing capacity "
            "in dense urban environments."
        )

        # ── Low-Latency ─────────────────────────────────────────────────────────
        self._add_divider()
        self._section("Low-Latency Network Slicing", section_font)

        self.urllcBtns = self._add_row(
            "Low-Latency Mode  [LowLatencyModeEnabled]",
            "LowLatencyModeEnabled — requests a URLLC (Ultra-Reliable Low-Latency "
            "Communications) network slice from the 5G core, targeting <1 ms "
            "round-trip for real-time applications like cloud gaming and AR."
        )

        # ── Standard cellular ───────────────────────────────────────────────────
        self._add_divider()
        self._section("Standard Cellular  (also on Home Screen & Cell. page)", section_font)

        self.dataRoamingBtns = self._add_row(
            "Data Roaming  [DataRoamingEnabled]",
            "DataRoamingEnabled — allows cellular data on foreign carrier networks."
        )
        self.volte2Btns = self._add_row(
            "VoLTE  [VoLTEEnabled]",
            "VoLTEEnabled — routes voice over LTE for HD audio quality."
        )
        self.lte2Btns = self._add_row(
            "LTE Radio  [LTEEnabled]",
            "LTEEnabled — controls whether LTE networks are permitted."
        )

        self.layout_main.addItem(
            QSpacerItem(20, 20, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)
        )

    def _section(self, text: str, font: QFont):
        lbl = QLabel(text)
        lbl.setFont(font)
        lbl.setStyleSheet("color: #e8e8e8; margin-top: 6px;")
        self.layout_main.addWidget(lbl)

    def _add_divider(self):
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setStyleSheet("QFrame { color: #414141; }")
        self.layout_main.addWidget(line)

    def _add_row(self, label_text: str, description: str) -> QHBoxLayout:
        row_widget = QWidget()
        row_layout = QHBoxLayout(row_widget)
        row_layout.setContentsMargins(0, 2, 0, 2)
        row_layout.setSpacing(12)

        info = QWidget()
        info_layout = QVBoxLayout(info)
        info_layout.setContentsMargins(0, 0, 0, 0)
        info_layout.setSpacing(2)
        name_lbl = QLabel(label_text)
        name_lbl.setStyleSheet("font-size: 14px;")
        desc_lbl = QLabel(description)
        desc_lbl.setStyleSheet("font-size: 11px; color: #888888;")
        desc_lbl.setWordWrap(True)
        info_layout.addWidget(name_lbl)
        info_layout.addWidget(desc_lbl)
        info.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        row_layout.addWidget(info)

        btn_container = QWidget()
        btn_layout = QHBoxLayout(btn_container)
        btn_layout.setContentsMargins(0, 0, 0, 0)
        btn_layout.setSpacing(0)
        row_layout.addWidget(btn_container)

        self.layout_main.addWidget(row_widget)
        return btn_layout

    def load_page(self):
        load_6g_advanced()
        load_cellular()
        self.createRadioBtns(TweakID.Cell6GEnabled, self.cell6GBtns)
        self.createRadioBtns(TweakID.CellmmWave, self.mmWaveBtns)
        self.createRadioBtns(TweakID.CellStandalone5G, self.saBtns)
        self.createRadioBtns(TweakID.CellNRDualConnectivity, self.nrDCBtns)
        self.createRadioBtns(TweakID.CellCarrierAgg, self.carrierAggBtns)
        self.createRadioBtns(TweakID.CellAdvancedMIMO, self.mimoBtns)
        self.createRadioBtns(TweakID.CellLowLatencyMode, self.urllcBtns)
        self.createRadioBtns(TweakID.CellularDataRoaming, self.dataRoamingBtns)
        self.createRadioBtns(TweakID.CellularVoLTE, self.volte2Btns)
        self.createRadioBtns(TweakID.CellularLTE, self.lte2Btns)
