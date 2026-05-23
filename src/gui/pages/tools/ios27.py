from PySide6.QtWidgets import (
    QWidget, QScrollArea, QVBoxLayout, QHBoxLayout,
    QLabel, QCheckBox, QFrame, QSpacerItem, QSizePolicy, QPushButton
)
from PySide6.QtCore import Qt

from ..page import Page
from src.tweaks.tweaks import tweaks, TweakID
from src.tweaks.tweak_loader import load_ios27, load_accessibility, _page_tweak_ids


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
    """Liquid Glass, Siri, Accessibility & Audio – all real tweaks, no BookRestore."""

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

    # ── UI construction ──────────────────────────────────────────────────────

    def _build_ui(self, layout: QVBoxLayout):

        # ── Enable / Disable All ─────────────────────────────────────────────
        btn_row = QHBoxLayout()
        btn_enable = QPushButton("Enable All")
        btn_enable.setStyleSheet(
            "QPushButton { background:#2a6ebb; color:#fff; border-radius:6px;"
            "padding:6px 18px; font-size:13px; }"
            "QPushButton:hover { background:#3580d4; }"
            "QPushButton:pressed { background:#1e5499; }")
        btn_enable.clicked.connect(self._enable_all)

        btn_disable = QPushButton("Disable All")
        btn_disable.setStyleSheet(
            "QPushButton { background:#555; color:#fff; border-radius:6px;"
            "padding:6px 18px; font-size:13px; }"
            "QPushButton:hover { background:#666; }"
            "QPushButton:pressed { background:#444; }")
        btn_disable.clicked.connect(self._disable_all)

        btn_row.addWidget(btn_enable)
        btn_row.addWidget(btn_disable)
        btn_row.addStretch()
        layout.addLayout(btn_row)
        layout.addWidget(_divider())

        # ── Siri ─────────────────────────────────────────────────────────────
        layout.addWidget(_section_label("Siri"))
        layout.addWidget(_divider())
        layout.addWidget(_row(TweakID.Siri2FloatingBubble,
            "Enable Siri",
            "Ensure Siri is active via managed preferences (AssistantEnabled)."))
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
            "Turn off the explicit language filter in Siri responses (SiriProfanityFilter=false)."))
        layout.addWidget(_row(TweakID.Siri2CallScreening,
            "Siri on Lock Screen",
            "Allow Siri from any lock screen state (AssistantAllowedForAnyLockscreen)."))

        # ── Liquid Glass per-app ──────────────────────────────────────────────
        layout.addWidget(_section_label("Liquid Glass – Per-App"))
        layout.addWidget(_divider())
        layout.addWidget(_row(TweakID.SolariumFFMessages,
            "Liquid Glass in Messages",
            "Enable Solarium Liquid Glass for Messages (Messages.Solarium feature flag)."))
        layout.addWidget(_row(TweakID.SolariumFFMaps,
            "Liquid Glass in Maps",
            "Enable Solarium Liquid Glass for Maps (Maps.Solarium)."))
        layout.addWidget(_row(TweakID.SolariumFFSafari,
            "Liquid Glass in Safari",
            "Enable Solarium rendering in Safari toolbars and panels (MobileSafari.Solarium)."))
        layout.addWidget(_row(TweakID.SolariumFFSpotlight,
            "Liquid Glass in Spotlight",
            "Enable Solarium for the Spotlight search UI (Spotlight.Solarium)."))
        layout.addWidget(_row(TweakID.SolariumFFControlCenter,
            "Liquid Glass in Control Centre",
            "Enable Solarium rendering for Control Centre modules (ControlCenter.Solarium)."))
        layout.addWidget(_row(TweakID.SolariumFFNotifications,
            "Liquid Glass Notification Banners",
            "Enable Solarium for notification banners (UserNotificationsUI.Solarium)."))
        layout.addWidget(_row(TweakID.SolariumFFWidgets,
            "Liquid Glass Widgets",
            "Enable Solarium Liquid Glass for home screen widgets (WidgetKit.Solarium)."))
        layout.addWidget(_row(TweakID.SolariumFFMusic,
            "Liquid Glass in Music",
            "Enable Solarium in the Music player and library (Music.Solarium)."))
        layout.addWidget(_row(TweakID.SolariumFFPodcasts,
            "Liquid Glass in Podcasts",
            "Enable Solarium in the Podcasts player (Podcasts.Solarium)."))
        layout.addWidget(_row(TweakID.SolariumFFPhone,
            "Liquid Glass in Phone",
            "Enable Solarium for the Phone dialer (Phone.Solarium)."))
        layout.addWidget(_row(TweakID.SolariumFFCalendar,
            "Liquid Glass in Calendar",
            "Enable Solarium for Calendar event views (Calendar.Solarium)."))
        layout.addWidget(_row(TweakID.SolariumFFReminders,
            "Liquid Glass in Reminders",
            "Enable Solarium for Reminders list rows (Reminders.Solarium)."))
        layout.addWidget(_row(TweakID.SolariumFFNotes,
            "Liquid Glass in Notes",
            "Enable Solarium in the Notes toolbar and panel (Notes.Solarium)."))

        # ── Liquid Glass fine-tuning ──────────────────────────────────────────
        layout.addWidget(_section_label("Liquid Glass – Fine-Tuning"))
        layout.addWidget(_divider())
        layout.addWidget(_row(TweakID.NoLiquidStatusBar,
            "Disable Glass on Status Bar",
            "Remove the specular glass material from the status bar (SBDisableGlassStatusBar)."))
        layout.addWidget(_row(TweakID.NoLiquidNotifications,
            "Disable Glass on Notifications",
            "Solid surfaces instead of Liquid Glass for banners (SBDisableGlassNotifications)."))
        layout.addWidget(_row(TweakID.SolariumHighContrast,
            "High Contrast Liquid Glass",
            "Increase contrast of glass layers for better legibility (SolariumHighContrast)."))
        layout.addWidget(_row(TweakID.SolariumForceLightTint,
            "Force Light Tint on Glass",
            "Always render Liquid Glass with a light tint (SolariumForceLightTint)."))
        layout.addWidget(_row(TweakID.SolariumMaxBlur,
            "Maximum Blur Radius",
            "Push blur radius of Liquid Glass surfaces to the maximum (SolariumMaxBlur)."))

        # ── SpringBoard ───────────────────────────────────────────────────────
        layout.addWidget(_section_label("SpringBoard"))
        layout.addWidget(_divider())
        layout.addWidget(_row(TweakID.SBShowBatteryPercentageAlways,
            "Always Show Battery Percentage",
            "Force battery percentage in the status bar (SBUIForceDisplayBatteryPercentageNew)."))
        layout.addWidget(_row(TweakID.SBHideHomeIndicator,
            "Hide Home Bar Indicator",
            "Hide the home indicator bar at the bottom of the screen (SBHideHomeIndicator)."))
        layout.addWidget(_row(TweakID.SBDisableParallaxEffect,
            "Disable Parallax / Motion Effect",
            "Disable the parallax depth effect on icons and wallpaper (SBDisableParallax)."))
        layout.addWidget(_row(TweakID.SBAlwaysGlassHeaders,
            "Always Show Glass Section Headers",
            "Keep home screen section labels with glass backgrounds visible (SBAlwaysShowGlassGroupHeaders)."))
        layout.addWidget(_row(TweakID.SBExpandedDynamicIsland,
            "Persistent Expanded Dynamic Island",
            "Keep Dynamic Island expanded with persistent content (SBEnableExpandedDynamicIslandPersistent)."))
        layout.addWidget(_row(TweakID.SBAlwaysShowClockDI,
            "Show Clock alongside Dynamic Island",
            "Keep the time visible when Dynamic Island is active (SBShowClockWithDynamicIsland)."))

        # ── Accessibility ────────────────────────────────────────────────────
        layout.addWidget(_section_label("Bedienungshilfen (Accessibility)"))
        layout.addWidget(_divider())
        layout.addWidget(_row(TweakID.A11yReduceMotion,
            "Bewegung reduzieren",
            "Reduces parallax and animation effects system-wide (ReduceMotionEnabled)."))
        layout.addWidget(_row(TweakID.A11yReduceTransparency,
            "Transparenz reduzieren",
            "Replaces blur/translucency with solid colors (ReduceTransparencyEnabled)."))
        layout.addWidget(_row(TweakID.A11yIncreaseContrast,
            "Kontrast erhöhen",
            "Increases contrast between foreground and background colors (IncreaseContrastEnabled)."))
        layout.addWidget(_row(TweakID.A11yDifferentiateColors,
            "Ohne Farbe unterscheiden",
            "Uses shapes/patterns in addition to color to convey information (DifferentiateWithoutColor)."))
        layout.addWidget(_row(TweakID.A11yBoldText,
            "Fettgedruckter Text",
            "Renders all system text in bold weight (BoldTextEnabled)."))
        layout.addWidget(_row(TweakID.A11yGrayscale,
            "Graustufen",
            "Displays the entire screen in grayscale (GrayscaleEnabled)."))
        layout.addWidget(_row(TweakID.A11yClassicInvert,
            "Klassische Farben umkehren",
            "Inverts all screen colors (InvertColorsEnabled)."))
        layout.addWidget(_row(TweakID.A11yEnhancedContrast,
            "Hintergrundkontrast erhöhen",
            "Enhances the contrast of the system background colors (EnhancedBackgroundContrastEnabled)."))
        layout.addWidget(_row(TweakID.A11yAssistiveTouch,
            "AssistiveTouch aktivieren",
            "Adds a floating on-screen button for device controls (AssistiveTouchEnabled)."))
        layout.addWidget(_row(TweakID.A11yClosedCaptions,
            "Untertitel & SDH",
            "Enables closed captions and subtitles for the deaf and hard of hearing (ClosedCaptionEnabled)."))
        layout.addWidget(_row(TweakID.A11ySpeakSelection,
            "Auswahl vorlesen",
            "Adds a Speak button when text is selected (SpeakSelectionEnabled)."))
        layout.addWidget(_row(TweakID.A11ySpeakAutoCorrect,
            "Autokorrektur vorlesen",
            "Speaks auto-corrections and auto-capitalisations as they are applied (SpeakAutoCorrectEnabled)."))
        layout.addWidget(_row(TweakID.A11ySpeakScreen,
            "Bildschirm vorlesen",
            "Reads the entire screen content when you swipe down with two fingers (SpeakScreenEnabled)."))
        layout.addWidget(_row(TweakID.A11yVoiceOver,
            "VoiceOver aktivieren",
            "Enables the screen reader for blind and low-vision users (VoiceOverTouchEnabled)."))
        layout.addWidget(_row(TweakID.A11yZoom,
            "Zoom aktivieren",
            "Enables the full-screen or window zoom magnifier (ZoomTouchEnabled)."))
        layout.addWidget(_row(TweakID.A11yOnOffLabels,
            "Ein/Aus-Beschriftungen",
            "Adds I/O labels to toggle switches for clarity (OnOffSwitchLabelsEnabled)."))
        layout.addWidget(_row(TweakID.A11yButtonShapes,
            "Tastenformen",
            "Adds visible shapes behind tappable text elements (ButtonShapesEnabled)."))
        layout.addWidget(_row(TweakID.A11yStickyKeys,
            "Klebrige Tasten",
            "Allows modifier keys to remain active after being pressed once (StickyKeysEnabled)."))
        layout.addWidget(_row(TweakID.A11ySlowKeys,
            "Langsame Tasten",
            "Adjusts the time between a key press and its acceptance (SlowKeysEnabled)."))
        layout.addWidget(_row(TweakID.A11yMouseKeys,
            "Maustasten",
            "Lets the numeric keypad control the pointer (MouseKeysEnabled)."))
        layout.addWidget(_row(TweakID.A11ySwitchControl,
            "Schaltersteuerung",
            "Enables Switch Control for alternative input devices (SwitchControlEnabled)."))
        layout.addWidget(_row(TweakID.A11yGuidedAccess,
            "Geführter Zugriff",
            "Locks the device to a single app and controls available features (GuidedAccessEnabled)."))
        layout.addWidget(_row(TweakID.A11yRTT,
            "RTT / TTY",
            "Enables real-time text for phone calls (RTTEnabled)."))
        layout.addWidget(_row(TweakID.A11yLEDFlash,
            "LED-Blitz für Hinweise",
            "Flashes the LED flash when alerts arrive (LEDFlashEnabled)."))
        layout.addWidget(_row(TweakID.A11yMonoAudio,
            "Mono-Audio",
            "Combines left and right audio channels into one (MonoAudioEnabled)."))
        layout.addWidget(_row(TweakID.A11yReduceWhitePoint,
            "Weißpunkt reduzieren",
            "Reduces the intensity of bright colors (ReduceWhitePointEnabled)."))
        layout.addWidget(_row(TweakID.A11yAutoAccessibility,
            "Bedienungshilfen automatisch aktivieren",
            "Allows system to automatically enable accessibility features (AutoAccessibilityEnabled)."))
        layout.addWidget(_row(TweakID.A11yHoverText,
            "Hover-Text",
            "Shows a large text magnifier when hovering over text (HoverTextEnabled)."))
        layout.addWidget(_row(TweakID.A11yLargePointer,
            "Großer Zeiger",
            "Increases the size of the pointer/cursor (LargePointerEnabled)."))
        layout.addWidget(_row(TweakID.A11yFullKeyboardAccess,
            "Vollständiger Tastaturzugriff",
            "Control the entire UI using only a keyboard (FullKeyboardAccessEnabled)."))

        # ── Audio Processing ──────────────────────────────────────────────────
        layout.addWidget(_section_label("Audio-Verarbeitung"))
        layout.addWidget(_divider())
        layout.addWidget(_row(TweakID.AudioSpatialDefault,
            "Spatial Audio Verarbeitung",
            "Enable CoreAudio's spatial audio processing pipeline (CoreAudio.SpatialAudioProcessing)."))
        layout.addWidget(_row(TweakID.AudioEnhancedSpeaker,
            "Enhanced Speaker Output",
            "Enable AVFoundation's enhanced speaker output stage (AVFoundation.EnhancedSpeakerOutput)."))
        layout.addWidget(_row(TweakID.AudioPersonalizedSpatial,
            "Personalisiertes Spatial Audio",
            "Enable personalised spatial audio rendering (AVFoundation.PersonalizedSpatialAudio)."))
        layout.addWidget(_row(TweakID.AudioBackgroundSounds,
            "Hintergrundklänge",
            "Enable extended background sounds feature flag (Accessibility.BackgroundSounds)."))
        layout.addWidget(_row(TweakID.AudioHeadphoneAccom,
            "Kopfhöreranpassungen",
            "Enable headphone accommodations for hearing (Accessibility.HeadphoneAccommodations)."))
        layout.addWidget(_row(TweakID.AudioLoudnessNorm,
            "Lautstärke-Normalisierung",
            "Enable AVFoundation loudness normalisation across media playback (AVFoundation.LoudnessNormalization)."))
        layout.addWidget(_row(TweakID.AudioSoundEffectsEnabled,
            "System-Sounds aktivieren",
            "Force system sound effects on via GlobalPreferences (SBSoundEffectsEnabled)."))
        layout.addWidget(_row(TweakID.AudioHapticsSync,
            "Audio-Haptics synchronisieren",
            "Enable synchronised audio+haptic feedback patterns (SBAudioHapticsSyncEnabled)."))

    # ── Enable / Disable All ─────────────────────────────────────────────────

    def _enable_all(self):
        for tid in _page_tweak_ids:
            if tid in tweaks:
                tweaks[tid].set_enabled(True)

    def _disable_all(self):
        for tid in _page_tweak_ids:
            if tid in tweaks:
                tweaks[tid].set_enabled(False)

    def load_page(self):
        load_ios27()
        load_accessibility()
