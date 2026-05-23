from PySide6.QtWidgets import (
    QWidget, QScrollArea, QVBoxLayout, QHBoxLayout,
    QLabel, QCheckBox, QRadioButton, QFrame, QSpacerItem, QSizePolicy
)
from PySide6.QtCore import Qt

from ..page import Page
from src.tweaks.tweaks import tweaks, TweakID
from src.tweaks.tweak_loader import load_ios27


# ── helpers ──────────────────────────────────────────────────────────────────

def _section_label(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setStyleSheet("font-size: 16px; font-weight: bold; color: #e8e8e8; margin-top: 8px;")
    return lbl


def _divider() -> QFrame:
    line = QFrame()
    line.setFrameShape(QFrame.Shape.HLine)
    line.setFrameShadow(QFrame.Shadow.Plain)
    line.setStyleSheet("color: #4B4B4B;")
    return line


def _tweak_card_ff(tweak_id: TweakID, title: str, description: str) -> QWidget:
    """Checkbox row for a FeatureFlagTweak."""
    card = QWidget()
    layout = QVBoxLayout(card)
    layout.setContentsMargins(0, 4, 0, 4)
    layout.setSpacing(2)

    chk = QCheckBox(title)
    chk.setStyleSheet("font-size: 14px;")
    chk.toggled.connect(lambda checked, k=tweak_id: tweaks[k].set_enabled(checked))
    layout.addWidget(chk)

    desc = QLabel(description)
    desc.setStyleSheet("font-size: 12px; color: #999999; padding-left: 22px;")
    desc.setWordWrap(True)
    layout.addWidget(desc)

    return card


def _tweak_card_plist(tweak_id: TweakID, title: str, description: str,
                      invert: bool = False) -> QWidget:
    """Default / Enabled / Disabled radio row for a BasicPlistTweak."""
    card = QWidget()
    layout = QVBoxLayout(card)
    layout.setContentsMargins(0, 4, 0, 4)
    layout.setSpacing(4)

    title_lbl = QLabel(title)
    title_lbl.setStyleSheet("font-size: 14px; font-weight: bold;")
    layout.addWidget(title_lbl)

    desc_lbl = QLabel(description)
    desc_lbl.setStyleSheet("font-size: 12px; color: #999999;")
    desc_lbl.setWordWrap(True)
    layout.addWidget(desc_lbl)

    btn_row = QHBoxLayout()
    btn_row.setSpacing(12)

    default_btn = QRadioButton("Default")
    default_btn.setChecked(True)
    default_btn.clicked.connect(lambda _, k=tweak_id: tweaks[k].set_enabled(False))

    enabled_btn = QRadioButton("Enabled")
    enabled_btn.clicked.connect(
        lambda _, k=tweak_id, inv=invert: tweaks[k].set_value(not inv))

    disabled_btn = QRadioButton("Disabled")
    disabled_btn.clicked.connect(
        lambda _, k=tweak_id, inv=invert: tweaks[k].set_value(inv))

    btn_row.addWidget(default_btn)
    btn_row.addWidget(enabled_btn)
    btn_row.addWidget(disabled_btn)
    btn_row.addItem(QSpacerItem(40, 20, QSizePolicy.Policy.Expanding,
                                 QSizePolicy.Policy.Minimum))
    layout.addLayout(btn_row)

    return card


# ── page class ───────────────────────────────────────────────────────────────

class iOS27Page(Page):
    """iOS 27 Concept + Siri 2.0 UI tweaks – fully self-contained dynamic page."""

    def __init__(self, ui, stacked_widget):
        super().__init__()
        self.ui = ui

        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(30, 30, 30, 30)
        content_layout.setSpacing(6)
        content_layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        self._build_ui(content_layout)

        content_layout.addItem(
            QSpacerItem(20, 40, QSizePolicy.Policy.Minimum,
                        QSizePolicy.Policy.Expanding))

        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setFrameShape(QFrame.Shape.NoFrame)
        self.scroll_area.setWidget(content_widget)

        stacked_widget.addWidget(self.scroll_area)
        self.page_index = stacked_widget.count() - 1

    # ── UI construction ──────────────────────────────────────────────────────

    def _build_ui(self, layout: QVBoxLayout):
        # ── Siri 2.0 ─────────────────────────────────────────────────────────
        layout.addWidget(_section_label("Siri 2.0"))
        layout.addWidget(_divider())

        layout.addWidget(_tweak_card_ff(
            TweakID.Siri2FloatingBubble,
            "Siri 2.0 Floating Bubble",
            "Show Siri as a floating orb/bubble instead of the full-screen overlay."))
        layout.addWidget(_tweak_card_ff(
            TweakID.Siri2AmbientMode,
            "Siri Ambient Always-On Mode",
            "Keep Siri in a low-power ambient listening state when plugged in."))
        layout.addWidget(_tweak_card_ff(
            TweakID.Siri2VisualResponse,
            "Siri 2.0 Visual Response Animations",
            "Enable the new fluid wave-and-pulse visual feedback during Siri responses."))
        layout.addWidget(_tweak_card_ff(
            TweakID.Siri2NaturalVoice,
            "Siri Natural Neural Voice",
            "Enable the next-generation neural TTS voice introduced in iOS 27."))
        layout.addWidget(_tweak_card_ff(
            TweakID.Siri2OnScreenContext,
            "Siri On-Screen Context Awareness",
            "Allow Siri to read and act on content currently visible on screen."))
        layout.addWidget(_tweak_card_ff(
            TweakID.Siri2CallScreening,
            "Siri Call Screening",
            "Let Siri answer unknown calls and transcribe the caller's message in real time."))
        layout.addWidget(_tweak_card_ff(
            TweakID.Siri2PersonalHistory,
            "Siri Personal Context / History",
            "Enable cross-session personal context so Siri remembers preferences over time."))
        layout.addWidget(_tweak_card_ff(
            TweakID.Siri2VisionProStyle,
            "Siri Vision Pro–Style Presentation",
            "Use the visionOS-inspired spatial Siri UI layout on iPhone."))

        # ── iOS 27 Home Screen ────────────────────────────────────────────────
        layout.addWidget(_section_label("iOS 27 Concept – Home Screen"))
        layout.addWidget(_divider())

        layout.addWidget(_tweak_card_ff(
            TweakID.iOS27LargeWidgets,
            "iOS 27 XL Widget Sizes",
            "Unlock extra-large widget slots on the home screen grid."))
        layout.addWidget(_tweak_card_ff(
            TweakID.iOS27HomeScreenRedesign,
            "iOS 27 Home Screen Grid",
            "Enable the redesigned adaptive icon grid layout introduced in iOS 27."))
        layout.addWidget(_tweak_card_ff(
            TweakID.iOS27AppLibraryRedesign,
            "iOS 27 App Library Redesign",
            "Enable the new categorised App Library with Liquid Glass cards."))
        layout.addWidget(_tweak_card_ff(
            TweakID.iOS27ContextMenuRedesign,
            "iOS 27 Context Menu Redesign",
            "Use the new full-width context menus with Liquid Glass background."))
        layout.addWidget(_tweak_card_ff(
            TweakID.iOS27AppSwitcherRedesign,
            "iOS 27 App Switcher",
            "Enable the carousel-style app switcher with glass cards."))

        # ── iOS 27 System UI ──────────────────────────────────────────────────
        layout.addWidget(_section_label("iOS 27 Concept – System UI"))
        layout.addWidget(_divider())

        layout.addWidget(_tweak_card_ff(
            TweakID.iOS27CCRedesign,
            "iOS 27 Control Centre Redesign",
            "Switch to the new modular, resizable Control Centre from iOS 27."))
        layout.addWidget(_tweak_card_ff(
            TweakID.iOS27NotificationsRedesign,
            "iOS 27 Notifications Redesign",
            "Enable grouped, stacked notification cards with Liquid Glass styling."))
        layout.addWidget(_tweak_card_ff(
            TweakID.iOS27LockScreenRedesign,
            "iOS 27 Lock Screen Redesign",
            "Enable the next-generation lock screen with depth-effect clock and glassy widgets."))
        layout.addWidget(_tweak_card_ff(
            TweakID.iOS27StatusBarRedesign,
            "iOS 27 Status Bar Redesign",
            "Use the condensed, always-glassy status bar style from iOS 27."))
        layout.addWidget(_tweak_card_ff(
            TweakID.iOS27ShareSheetRedesign,
            "iOS 27 Share Sheet Redesign",
            "Enable the new compact Share Sheet with Liquid Glass surface."))

        # ── Liquid Glass 2.0 Extensions ───────────────────────────────────────
        layout.addWidget(_section_label("Liquid Glass 2.0 – Per-App Extensions"))
        layout.addWidget(_divider())

        layout.addWidget(_tweak_card_ff(
            TweakID.SolariumFFMessages,
            "Liquid Glass in Messages",
            "Apply Solarium Liquid Glass rendering to the Messages app UI."))
        layout.addWidget(_tweak_card_ff(
            TweakID.SolariumFFMaps,
            "Liquid Glass in Maps",
            "Apply Solarium Liquid Glass to Maps cards, sheets, and overlays."))
        layout.addWidget(_tweak_card_ff(
            TweakID.SolariumFFSafari,
            "Liquid Glass in Safari",
            "Apply Solarium rendering to Safari toolbars and overlay panels."))
        layout.addWidget(_tweak_card_ff(
            TweakID.SolariumFFSpotlight,
            "Liquid Glass in Spotlight",
            "Apply Solarium Liquid Glass to the Spotlight search interface."))
        layout.addWidget(_tweak_card_ff(
            TweakID.SolariumFFControlCenter,
            "Liquid Glass in Control Centre",
            "Apply Solarium rendering to Control Centre modules and panels."))
        layout.addWidget(_tweak_card_ff(
            TweakID.SolariumFFNotifications,
            "Liquid Glass Notifications",
            "Apply Solarium Liquid Glass to notification banners and sheets."))
        layout.addWidget(_tweak_card_ff(
            TweakID.SolariumFFWidgets,
            "Liquid Glass Widgets",
            "Apply Solarium Liquid Glass background to home screen widgets."))

        # ── Liquid Glass Fine-Tuning ───────────────────────────────────────────
        layout.addWidget(_section_label("Liquid Glass – Fine-Tuning"))
        layout.addWidget(_divider())

        layout.addWidget(_tweak_card_plist(
            TweakID.NoLiquidStatusBar,
            "Disable Glass on Status Bar",
            "Remove the specular / glass material from the status bar."))
        layout.addWidget(_tweak_card_plist(
            TweakID.NoLiquidNotifications,
            "Disable Glass on Notifications",
            "Use solid surfaces instead of Liquid Glass for notification banners."))
        layout.addWidget(_tweak_card_plist(
            TweakID.SolariumHighContrast,
            "High Contrast Liquid Glass",
            "Increase contrast of glass layers for better readability."))
        layout.addWidget(_tweak_card_plist(
            TweakID.SolariumForceLightTint,
            "Force Light Tint on Glass",
            "Always render Liquid Glass with a light tint regardless of appearance mode."))
        layout.addWidget(_tweak_card_plist(
            TweakID.SolariumMaxBlur,
            "Maximum Blur Radius",
            "Push blur radius of Liquid Glass surfaces to the maximum supported value."))

        # ── SpringBoard iOS 27 ────────────────────────────────────────────────
        layout.addWidget(_section_label("SpringBoard – iOS 27 Options"))
        layout.addWidget(_divider())

        layout.addWidget(_tweak_card_plist(
            TweakID.SBAlwaysGlassHeaders,
            "Always Show Glass Section Headers",
            "Keep home screen section labels visible with glass backgrounds at all times."))
        layout.addWidget(_tweak_card_plist(
            TweakID.SBExpandedDynamicIsland,
            "Expanded Dynamic Island",
            "Enable expanded Dynamic Island interactions and persistent content."))
        layout.addWidget(_tweak_card_plist(
            TweakID.SBShowWeatherLockScreen,
            "Live Weather on Lock Screen",
            "Show animated live weather data directly on the lock screen background."))
        layout.addWidget(_tweak_card_plist(
            TweakID.SBEnhancedHaptics,
            "Enhanced System Haptics",
            "Enable richer haptic feedback patterns for SpringBoard interactions."))
        layout.addWidget(_tweak_card_plist(
            TweakID.SBShowBatteryPercentageAlways,
            "Always Show Battery Percentage",
            "Force the battery percentage to appear in the status bar at all times."))
        layout.addWidget(_tweak_card_plist(
            TweakID.SBHideHomeIndicator,
            "Hide Home Bar Indicator",
            "Hide the home indicator bar at the bottom of the screen."))
        layout.addWidget(_tweak_card_plist(
            TweakID.SBDisableParallaxEffect,
            "Disable Parallax / Motion Effect",
            "Disable the parallax depth effect on home screen icons and wallpaper."))

    def load_page(self):
        load_ios27()
