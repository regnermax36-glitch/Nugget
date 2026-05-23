from PySide6.QtWidgets import (
    QWidget, QScrollArea, QVBoxLayout,
    QLabel, QCheckBox, QFrame, QSpacerItem, QSizePolicy
)
from PySide6.QtCore import Qt

from ..page import Page
from src.tweaks.tweaks import tweaks, TweakID
from src.tweaks.tweak_loader import load_ios27


def _section_label(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setStyleSheet(
        "font-size: 16px; font-weight: bold; color: #e8e8e8; margin-top: 10px;")
    return lbl


def _divider() -> QFrame:
    line = QFrame()
    line.setFrameShape(QFrame.Shape.HLine)
    line.setFrameShadow(QFrame.Shadow.Plain)
    line.setStyleSheet("color: #4B4B4B;")
    return line


def _row(tweak_id: TweakID, title: str, description: str) -> QWidget:
    card = QWidget()
    layout = QVBoxLayout(card)
    layout.setContentsMargins(0, 3, 0, 3)
    layout.setSpacing(2)

    chk = QCheckBox(title)
    chk.setStyleSheet("font-size: 14px;")
    chk.toggled.connect(lambda checked, k=tweak_id: tweaks[k].set_enabled(checked))
    layout.addWidget(chk)

    desc = QLabel(description)
    desc.setStyleSheet("font-size: 12px; color: #888888; padding-left: 22px;")
    desc.setWordWrap(True)
    layout.addWidget(desc)

    return card


class iOS27Page(Page):
    """Liquid Glass & Siri – real tweak page, no BookRestore."""

    def __init__(self, ui, stacked_widget):
        super().__init__()
        self.ui = ui

        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(30, 30, 30, 30)
        content_layout.setSpacing(4)
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

    def _build_ui(self, layout: QVBoxLayout):

        # ── Siri ─────────────────────────────────────────────────────────────
        layout.addWidget(_section_label("Siri"))
        layout.addWidget(_divider())
        layout.addWidget(_row(TweakID.Siri2FloatingBubble,
            "Enable Siri",
            "Ensure Siri (AssistantEnabled) is active via managed preferences."))
        layout.addWidget(_row(TweakID.Siri2AmbientMode,
            "Hey Siri / Voice Trigger",
            "Allow always-on voice activation (VoiceTriggerEnabled)."))
        layout.addWidget(_row(TweakID.Siri2VisualResponse,
            "Siri Button Access",
            "Allow Siri invocation from the side/home button (UIAssistantEnabled)."))
        layout.addWidget(_row(TweakID.Siri2NaturalVoice,
            "Type to Siri",
            "Enable keyboard input for Siri queries (KeyboardEnabled)."))
        layout.addWidget(_row(TweakID.Siri2OnScreenContext,
            "Disable Siri Profanity Filter",
            "Turn off the explicit language filter in Siri responses."))
        layout.addWidget(_row(TweakID.Siri2CallScreening,
            "Siri on Lock Screen",
            "Allow Siri to be invoked from any lock screen state (AssistantAllowedForAnyLockscreen)."))

        # ── Liquid Glass per-app ──────────────────────────────────────────────
        layout.addWidget(_section_label("Liquid Glass – Per-App"))
        layout.addWidget(_divider())
        layout.addWidget(_row(TweakID.SolariumFFMessages,
            "Liquid Glass in Messages",
            "Enable Solarium Liquid Glass rendering for the Messages app (Messages.Solarium feature flag)."))
        layout.addWidget(_row(TweakID.SolariumFFMaps,
            "Liquid Glass in Maps",
            "Enable Solarium Liquid Glass for Maps cards and overlays (Maps.Solarium)."))
        layout.addWidget(_row(TweakID.SolariumFFSafari,
            "Liquid Glass in Safari",
            "Enable Solarium rendering in Safari toolbars and panels (MobileSafari.Solarium)."))
        layout.addWidget(_row(TweakID.SolariumFFSpotlight,
            "Liquid Glass in Spotlight",
            "Enable Solarium Liquid Glass for the Spotlight search UI (Spotlight.Solarium)."))
        layout.addWidget(_row(TweakID.SolariumFFControlCenter,
            "Liquid Glass in Control Centre",
            "Enable Solarium rendering for Control Centre modules (ControlCenter.Solarium)."))
        layout.addWidget(_row(TweakID.SolariumFFNotifications,
            "Liquid Glass Notification Banners",
            "Enable Solarium rendering for notification banners (UserNotificationsUI.Solarium)."))
        layout.addWidget(_row(TweakID.SolariumFFWidgets,
            "Liquid Glass Widgets",
            "Enable Solarium Liquid Glass background for home screen widgets (WidgetKit.Solarium)."))
        layout.addWidget(_row(TweakID.SolariumFFMusic,
            "Liquid Glass in Music",
            "Enable Solarium rendering in the Music player and library (Music.Solarium)."))
        layout.addWidget(_row(TweakID.SolariumFFPodcasts,
            "Liquid Glass in Podcasts",
            "Enable Solarium rendering in the Podcasts player (Podcasts.Solarium)."))
        layout.addWidget(_row(TweakID.SolariumFFPhone,
            "Liquid Glass in Phone",
            "Enable Solarium Liquid Glass for the Phone dialer (Phone.Solarium)."))
        layout.addWidget(_row(TweakID.SolariumFFCalendar,
            "Liquid Glass in Calendar",
            "Enable Solarium rendering for Calendar event views (Calendar.Solarium)."))
        layout.addWidget(_row(TweakID.SolariumFFReminders,
            "Liquid Glass in Reminders",
            "Enable Solarium rendering for Reminders list rows (Reminders.Solarium)."))
        layout.addWidget(_row(TweakID.SolariumFFNotes,
            "Liquid Glass in Notes",
            "Enable Solarium rendering in the Notes toolbar and panel (Notes.Solarium)."))

        # ── Liquid Glass fine-tuning ──────────────────────────────────────────
        layout.addWidget(_section_label("Liquid Glass – Fine-Tuning"))
        layout.addWidget(_divider())
        layout.addWidget(_row(TweakID.NoLiquidStatusBar,
            "Disable Glass on Status Bar",
            "Remove the specular / glass material from the status bar (SBDisableGlassStatusBar)."))
        layout.addWidget(_row(TweakID.NoLiquidNotifications,
            "Disable Glass on Notifications",
            "Use solid surfaces instead of Liquid Glass for notification banners (SBDisableGlassNotifications)."))
        layout.addWidget(_row(TweakID.SolariumHighContrast,
            "High Contrast Liquid Glass",
            "Increase contrast of glass layers for better legibility (SolariumHighContrast)."))
        layout.addWidget(_row(TweakID.SolariumForceLightTint,
            "Force Light Tint on Glass",
            "Always render Liquid Glass with a light tint regardless of dark/light mode (SolariumForceLightTint)."))
        layout.addWidget(_row(TweakID.SolariumMaxBlur,
            "Maximum Blur Radius",
            "Push the blur radius of Liquid Glass surfaces to the maximum value (SolariumMaxBlur)."))

        # ── SpringBoard ───────────────────────────────────────────────────────
        layout.addWidget(_section_label("SpringBoard"))
        layout.addWidget(_divider())
        layout.addWidget(_row(TweakID.SBShowBatteryPercentageAlways,
            "Always Show Battery Percentage",
            "Force battery percentage in the status bar at all times (SBUIForceDisplayBatteryPercentageNew)."))
        layout.addWidget(_row(TweakID.SBHideHomeIndicator,
            "Hide Home Bar Indicator",
            "Hide the home indicator bar at the bottom of the screen (SBHideHomeIndicator)."))
        layout.addWidget(_row(TweakID.SBDisableParallaxEffect,
            "Disable Parallax / Motion Effect",
            "Disable the parallax depth effect on home screen icons and wallpaper (SBDisableParallax)."))
        layout.addWidget(_row(TweakID.SBAlwaysGlassHeaders,
            "Always Show Glass Section Headers",
            "Keep home screen section labels with glass backgrounds always visible (SBAlwaysShowGlassGroupHeaders)."))
        layout.addWidget(_row(TweakID.SBExpandedDynamicIsland,
            "Persistent Expanded Dynamic Island",
            "Keep Dynamic Island expanded with persistent content glyphs (SBEnableExpandedDynamicIslandPersistent)."))
        layout.addWidget(_row(TweakID.SBAlwaysShowClockDI,
            "Show Clock alongside Dynamic Island",
            "Keep the time visible in the corner when Dynamic Island is active (SBShowClockWithDynamicIsland)."))

    def load_page(self):
        load_ios27()
