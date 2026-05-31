from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QScrollArea,
    QFrame, QSizePolicy, QSpacerItem
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont

from ..page import Page
from src.tweaks.tweak_loader import load_siri_two, load_ios2627_layout
from src.tweaks.tweaks import TweakID


class SiriTwoPage(Page, QWidget):
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

        title = QLabel("Siri 2.0 + iOS 26/27 UI")
        title.setFont(title_font)
        self.layout_main.addWidget(title)

        subtitle = QLabel(
            "Enable WWDC 2026 Siri 2.0 conversational UI, voice design, and "
            "mesh/glass orb visuals. Also unlock iOS 26 and iOS 27 layout feature "
            "flags for adaptive sidebars, fluid transitions, and the floating sheet "
            "presentation style."
        )
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet("color: #aaaaaa; font-size: 13px;")
        self.layout_main.addWidget(subtitle)

        self._add_divider()
        self._section("Siri 2.0 — Conversational UI (WWDC 2026)", section_font)

        self.siri2NewUIBtns = self._add_row(
            "Siri 2.0 New Conversational UI",
            "Enables the WWDC 2026 redesigned Siri conversational interface and visual refresh."
        )
        self.siri2VoiceDesignBtns = self._add_row(
            "Siri Neural Voice Design V2",
            "High-fidelity neural voice with improved naturalness and prosody."
        )
        self.siri2MeshBgBtns = self._add_row(
            "Siri Mesh Animated Background",
            "Animated mesh / ambient background behind the Siri response card."
        )
        self.siri2GlassOrbBtns = self._add_row(
            "Siri Glass Orb Design",
            "Liquid-glass orb visual for Siri activation (Solarium-integrated)."
        )
        self.siri2OnDeviceBtns = self._add_row(
            "Extended On-Device Inference",
            "Allows longer on-device Siri context window for complex requests."
        )
        self.siri2ProactiveBtns = self._add_row(
            "Proactive Context Engine V2",
            "Screen-awareness and proactive suggestion engine for Siri 2.0."
        )

        self._add_divider()
        self._section("iOS 26 Layout Feature Flags", section_font)

        self.ios26FloatingSheetBtns = self._add_row(
            "Floating Sheet Presentation",
            "Detached floating modal sheets with adaptive corner radius (UIKit)."
        )
        self.ios26CompactTabBtns = self._add_row(
            "Compact Tab Bar Layout",
            "Denser tab bar with Solarium glass material (SpringBoard)."
        )

        self._add_divider()
        self._section("iOS 27 Layout Feature Flags", section_font)

        self.ios27FluidBtns = self._add_row(
            "Fluid Navigation Transitions V2",
            "Zoom-based navigation transitions with spring physics (UIKit)."
        )
        self.ios27SidebarBtns = self._add_row(
            "Adaptive Collapsible Sidebar",
            "Context-aware collapsible sidebar for iPad/iPhone split views."
        )
        self.ios27SwipeBtns = self._add_row(
            "Enhanced Swipe Navigation V2",
            "Extended gesture navigation system across SpringBoard."
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
        load_siri_two()
        load_ios2627_layout()

        self.createRadioBtns(TweakID.Siri2NewUI, self.siri2NewUIBtns)
        self.createRadioBtns(TweakID.Siri2VoiceDesign, self.siri2VoiceDesignBtns)
        self.createRadioBtns(TweakID.Siri2MeshBackground, self.siri2MeshBgBtns)
        self.createRadioBtns(TweakID.Siri2GlassOrb, self.siri2GlassOrbBtns)
        self.createRadioBtns(TweakID.Siri2OnDeviceExtended, self.siri2OnDeviceBtns)
        self.createRadioBtns(TweakID.Siri2ProactiveContext, self.siri2ProactiveBtns)

        self.createRadioBtns(TweakID.iOS26FloatingSheetUI, self.ios26FloatingSheetBtns)
        self.createRadioBtns(TweakID.iOS26CompactTabBar, self.ios26CompactTabBtns)

        self.createRadioBtns(TweakID.iOS27FluidTransitions, self.ios27FluidBtns)
        self.createRadioBtns(TweakID.iOS27AdaptiveSidebar, self.ios27SidebarBtns)
        self.createRadioBtns(TweakID.iOS27SwipeNavigation, self.ios27SwipeBtns)
