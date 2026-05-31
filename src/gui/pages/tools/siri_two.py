from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QScrollArea,
    QFrame, QSizePolicy, QSpacerItem
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont

from ..page import Page
from src.tweaks.tweak_loader import load_homescreen_dock, load_cellular
from src.tweaks.tweaks import TweakID


class SiriTwoPage(Page, QWidget):
    """Home Screen, Dock, Animations, and Cellular tweaks.
    All keys target Managed Preferences plists read by SpringBoard,
    UIKit, and CoreTelephony — applied via the original sparserestore path."""

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

        title = QLabel("Home Screen, Dock & Cellular")
        title.setFont(title_font)
        self.layout_main.addWidget(title)

        subtitle = QLabel(
            "Real SpringBoard managed-preference keys for the home screen, dock, "
            "and system animations — plus CoreTelephony managed-preference keys "
            "for modem/radio settings. All applied via sparserestore."
        )
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet("color: #aaaaaa; font-size: 13px;")
        self.layout_main.addWidget(subtitle)

        # ── Home Screen ────────────────────────────────────────────────────────
        self._add_divider()
        self._section("Home Screen Layout", section_font)

        self.homeRotationBtns = self._add_row(
            "Landscape Home Screen",
            "SBAllowHomeScreenRotation — lets the home screen rotate to landscape "
            "just like apps do (SpringBoard reads this from com.apple.springboard.plist)."
        )
        self.hideIconLabelsBtns = self._add_row(
            "Hide Icon Text Labels",
            "SBHideHomeScreenIconLabels — removes app name labels beneath all home "
            "screen icons for a cleaner look."
        )
        self.hideBadgesBtns = self._add_row(
            "Hide Notification Badges",
            "SBHideIconBadges — suppresses the red badge dot on every icon, "
            "keeping the home screen uncluttered."
        )
        self.batteryPctBtns = self._add_row(
            "Show Battery Percentage",
            "SBShowBatteryPercentage — forces the numeric battery percentage to "
            "appear in the status bar even on devices that hide it by default."
        )

        # ── Dock ───────────────────────────────────────────────────────────────
        self._add_divider()
        self._section("Dock", section_font)

        self.hideDockBgBtns = self._add_row(
            "Hide Dock Background",
            "SBHideDockBackground — removes the frosted-glass blur behind the "
            "dock, leaving only the icons floating above the wallpaper."
        )
        self.disableASBlurBtns = self._add_row(
            "Disable App-Switcher Blur",
            "SBDisableAppSwitcherBlurBackground — removes the background blur in "
            "the app switcher for a sharper, faster card view."
        )

        # ── Animations ─────────────────────────────────────────────────────────
        self._add_divider()
        self._section("System Animations  (UIAnimationDragCoefficient)", section_font)

        self.animFastBtns = self._add_row(
            "2× Faster Animations  [0.5]",
            "UIAnimationDragCoefficient = 0.5 in .GlobalPreferences — UIKit reads "
            "this at launch and scales every spring/duration by this factor. "
            "Only enable one speed at a time."
        )
        self.animSlowBtns = self._add_row(
            "Slow-Motion Animations  [10.0]",
            "UIAnimationDragCoefficient = 10.0 — stretches every animation to "
            "10× its normal duration, useful for inspecting transitions."
        )

        # ── Cellular & Modem ───────────────────────────────────────────────────
        self._add_divider()
        self._section("Cellular & Modem  (com.apple.coretelephony)", section_font)

        self.dataRoamingBtns = self._add_row(
            "Data Roaming",
            "DataRoamingEnabled — enables cellular data while roaming on foreign "
            "networks (CoreTelephony / CommCenter reads this key)."
        )
        self.enable5GBtns = self._add_row(
            "5G Radio",
            "5GEnabled — allows the modem to connect to 5G NR networks when "
            "coverage is available."
        )
        self.volteBtns = self._add_row(
            "Voice over LTE (VoLTE)",
            "VoLTEEnabled — routes voice calls over the LTE data channel for "
            "HD call quality and simultaneous voice + data."
        )
        self.wifiCallingBtns = self._add_row(
            "Wi-Fi Calling",
            "WiFiCallingEnabled — allows the device to place and receive calls "
            "over a Wi-Fi connection when cellular signal is weak."
        )
        self.hdVoiceBtns = self._add_row(
            "HD Voice (AMR-WB / EVS)",
            "HDVoiceEnabled — enables wideband and EVS voice codecs for higher "
            "fidelity audio on supported carrier networks."
        )
        self.lteBtns = self._add_row(
            "LTE Radio",
            "LTEEnabled — allows the modem to use LTE networks. Disabling forces "
            "the device back to 3G/2G."
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
        load_homescreen_dock()
        load_cellular()

        # Home screen
        self.createRadioBtns(TweakID.HomeScreenRotation, self.homeRotationBtns)
        self.createRadioBtns(TweakID.HideIconLabels, self.hideIconLabelsBtns)
        self.createRadioBtns(TweakID.HideNotificationBadges, self.hideBadgesBtns)
        self.createRadioBtns(TweakID.ShowBatteryPercentage, self.batteryPctBtns)

        # Dock
        self.createRadioBtns(TweakID.HideDockBackground, self.hideDockBgBtns)
        self.createRadioBtns(TweakID.DisableAppSwitcherBlur, self.disableASBlurBtns)

        # Animations — use createToggleBtns so the preset float value is not overwritten
        self.createToggleBtns(TweakID.AnimationSpeedFast, self.animFastBtns)
        self.createToggleBtns(TweakID.AnimationSpeedSlow, self.animSlowBtns)

        # Cellular
        self.createRadioBtns(TweakID.CellularDataRoaming, self.dataRoamingBtns)
        self.createRadioBtns(TweakID.Cellular5G, self.enable5GBtns)
        self.createRadioBtns(TweakID.CellularVoLTE, self.volteBtns)
        self.createRadioBtns(TweakID.CellularWiFiCalling, self.wifiCallingBtns)
        self.createRadioBtns(TweakID.CellularHDVoice, self.hdVoiceBtns)
        self.createRadioBtns(TweakID.CellularLTE, self.lteBtns)
