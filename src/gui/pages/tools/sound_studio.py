from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QScrollArea,
    QFrame, QSizePolicy, QSpacerItem
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont

from ..page import Page
from src.tweaks.tweak_loader import load_sound_studio
from src.tweaks.tweaks import TweakID


class SoundStudioPage(Page, QWidget):
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

        title = QLabel("Sound Studio")
        title.setFont(title_font)
        self.layout_main.addWidget(title)

        subtitle = QLabel(
            "MaxRegner revolutionary audio customization — control every system "
            "sound, voice quality, spatial audio, and media playback behavior."
        )
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet("color: #aaaaaa; font-size: 13px;")
        self.layout_main.addWidget(subtitle)

        self._add_divider()

        self._section("Keyboard & UI Feedback", section_font)
        self.keyboardFeedbackBtns = self._add_row(
            "Keyboard Click Sounds",
            "Enable tactile click sounds on every keystroke (UIKit)."
        )
        self.systemUIEffectsBtns = self._add_row(
            "System UI Sound Effects",
            "Global tap / alert / notification chime layer."
        )
        self.volumeHUDBtns = self._add_row(
            "Volume Change HUD Sound",
            "Play a tone when the ringer volume changes."
        )

        self._add_divider()
        self._section("Alerts & Notifications", section_font)
        self.screenshotDisableBtns = self._add_row(
            "Disable Screenshot Shutter",
            "Silence the camera click when taking a screenshot."
        )
        self.chargeAlertBtns = self._add_row(
            "Charge Connected Chime",
            "Play a sound when power is plugged in."
        )
        self.slowChargeAlertBtns = self._add_row(
            "Slow Charge Warning Sound",
            "Alert when device is charging slowly."
        )
        self.lowBatteryVoiceBtns = self._add_row(
            "Low Battery Voice Announcement",
            "Speak the battery percentage aloud when critically low."
        )
        self.btChimeBtns = self._add_row(
            "Bluetooth Connection Chime",
            "Play a tone on BT device connect / disconnect."
        )

        self._add_divider()
        self._section("Ringer & Haptics", section_font)
        self.ringerHapticBtns = self._add_row(
            "Ringer + Haptic Sync",
            "Keep vibration in sync with ringer audio waveform for richer feel."
        )

        self._add_divider()
        self._section("Spatial & Hi-Fi Audio", section_font)
        self.spatialAudioBtns = self._add_row(
            "Force Spatial Audio",
            "Force AVFoundation spatial audio engine for all media output."
        )
        self.duckOthersBtns = self._add_row(
            "Duck Other Apps During Playback",
            "Lower background app audio while media plays."
        )
        self.headphoneAnalysisBtns = self._add_row(
            "Headphone Acoustic Analysis",
            "Real-time headphone audio analysis for playback optimization."
        )

        self._add_divider()
        self._section("Voice & Calls", section_font)
        self.callVoiceEnhanceBtns = self._add_row(
            "Enhanced Call Voice Processing",
            "Enable advanced CoreTelephony noise reduction and voice clarity."
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

        self.layout_main.addWidget(row_widget)
        return btn_layout

    def load_page(self):
        load_sound_studio()

        self.createRadioBtns(TweakID.SoundKeyboardFeedback, self.keyboardFeedbackBtns)
        self.createRadioBtns(TweakID.SoundSystemUIEffects, self.systemUIEffectsBtns)
        self.createRadioBtns(TweakID.SoundVolumeHUD, self.volumeHUDBtns)
        self.createRadioBtns(TweakID.SoundScreenshotDisable, self.screenshotDisableBtns)
        self.createRadioBtns(TweakID.SoundChargeAlert, self.chargeAlertBtns)
        self.createRadioBtns(TweakID.SoundSlowChargeAlert, self.slowChargeAlertBtns)
        self.createRadioBtns(TweakID.SoundLowBatteryVoice, self.lowBatteryVoiceBtns)
        self.createRadioBtns(TweakID.SoundBTConnectionChime, self.btChimeBtns)
        self.createRadioBtns(TweakID.SoundRingerHapticSync, self.ringerHapticBtns)
        self.createRadioBtns(TweakID.SoundSpatialAudioForce, self.spatialAudioBtns)
        self.createRadioBtns(TweakID.SoundDuckOthers, self.duckOthersBtns)
        self.createRadioBtns(TweakID.SoundMediaPlaybackAnalysis, self.headphoneAnalysisBtns)
        self.createRadioBtns(TweakID.SoundCallVoiceEnhance, self.callVoiceEnhanceBtns)
