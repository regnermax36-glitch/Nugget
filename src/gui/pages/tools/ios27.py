from PySide6.QtWidgets import (
    QWidget, QScrollArea, QVBoxLayout, QHBoxLayout,
    QLabel, QCheckBox, QFrame, QSpacerItem, QSizePolicy, QPushButton
)
from PySide6.QtCore import Qt

from ..page import Page
from src.tweaks.tweaks import tweaks, TweakID
from src.tweaks.tweak_loader import (
    load_ios27, load_mros_solarium_extra, load_mros_real_prefs,
    load_mros_dock_nav, load_mros_alien_colors,
    load_mros_sound_engine, load_mros_siri_v2,
    _page_tweak_ids, MAXREGNEROS_MODE_IDS
)

# module-level checkbox registry — populated during _build_ui, synced in load_page
_checkbox_map: dict = {}


# ── helpers ──────────────────────────────────────────────────────────────────

def _hdr(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setStyleSheet(
        "font-size:15px;font-weight:bold;color:#c8d8f0;margin-top:12px;")
    return lbl


def _div() -> QFrame:
    line = QFrame()
    line.setFrameShape(QFrame.Shape.HLine)
    line.setFrameShadow(QFrame.Shadow.Plain)
    line.setStyleSheet("color:#3a3a4a;")
    return line


def _row(tweak_id: TweakID, title: str, desc: str) -> QWidget:
    card = QWidget()
    lay = QVBoxLayout(card)
    lay.setContentsMargins(0, 2, 0, 2)
    lay.setSpacing(1)
    chk = QCheckBox(title)
    chk.setStyleSheet("font-size:13px;")
    chk.toggled.connect(lambda v, k=tweak_id: tweaks[k].set_enabled(v))
    _checkbox_map[tweak_id] = chk
    lay.addWidget(chk)
    lbl = QLabel(desc)
    lbl.setStyleSheet("font-size:11px;color:#777;padding-left:20px;")
    lbl.setWordWrap(True)
    lay.addWidget(lbl)
    return card


def _btn(label: str, color: str, hover: str, pressed: str) -> QPushButton:
    b = QPushButton(label)
    b.setStyleSheet(
        f"QPushButton{{background:{color};color:#fff;border-radius:6px;"
        f"padding:5px 14px;font-size:12px;font-weight:bold;}}"
        f"QPushButton:hover{{background:{hover};}}"
        f"QPushButton:pressed{{background:{pressed};}}"
    )
    return b


# ── page ─────────────────────────────────────────────────────────────────────

class iOS27Page(Page):
    """maxregnerOS – full system-wide feature flag & managed-pref overhaul."""

    def __init__(self, ui, stacked_widget):
        super().__init__()
        self.ui = ui
        cw = QWidget()
        cl = QVBoxLayout(cw)
        cl.setContentsMargins(28, 24, 28, 24)
        cl.setSpacing(3)
        cl.setAlignment(Qt.AlignmentFlag.AlignTop)
        self._build_ui(cl)
        cl.addItem(QSpacerItem(20, 40, QSizePolicy.Policy.Minimum,
                               QSizePolicy.Policy.Expanding))
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setFrameShape(QFrame.Shape.NoFrame)
        self.scroll_area.setWidget(cw)
        stacked_widget.addWidget(self.scroll_area)
        self.page_index = stacked_widget.count() - 1

    def _build_ui(self, L: QVBoxLayout):

        # ── Brand header ─────────────────────────────────────────────────────
        brand = QLabel("mROS")
        brand.setStyleSheet(
            "font-size:32px;font-weight:900;color:#7eb8f7;"
            "letter-spacing:4px;margin-bottom:2px;")
        sub = QLabel("maxregnerOS  ·  Beyond Any Phone  ·  All Pre-Enabled  ·  No BookRestore")
        sub.setStyleSheet("font-size:11px;color:#555;margin-bottom:8px;")
        L.addWidget(brand)
        L.addWidget(sub)

        # ── Action buttons ───────────────────────────────────────────────────
        row = QHBoxLayout()
        b_all  = _btn("⚡ mROS Beast Mode", "#1a5fb4","#2a6ebb","#0f3a7a")
        b_on   = _btn("Enable All",          "#2d6a2d","#3d8a3d","#1f4f1f")
        b_off  = _btn("Disable All",         "#555",   "#666",   "#444"  )
        b_all.clicked.connect(self._maxregneros_mode)
        b_on.clicked.connect(self._enable_all)
        b_off.clicked.connect(self._disable_all)
        for b in (b_all, b_on, b_off):
            row.addWidget(b)
        row.addStretch()
        L.addLayout(row)
        L.addWidget(_div())

        # ── Siri ─────────────────────────────────────────────────────────────
        L.addWidget(_hdr("Siri — MDM Managed Preferences"))
        L.addWidget(_div())
        L.addWidget(_row(TweakID.Siri2FloatingBubble,
            "Enable Siri", "Force Siri active via MDM (AssistantEnabled)."))
        L.addWidget(_row(TweakID.Siri2AmbientMode,
            "Hey Siri / Voice Trigger", "Always-on voice activation (VoiceTriggerEnabled)."))
        L.addWidget(_row(TweakID.Siri2VisualResponse,
            "Siri Button Access", "Siri via side/home button (UIAssistantEnabled)."))
        L.addWidget(_row(TweakID.Siri2NaturalVoice,
            "Type to Siri", "Keyboard input for Siri (KeyboardEnabled)."))
        L.addWidget(_row(TweakID.Siri2OnScreenContext,
            "Disable Profanity Filter", "Remove Siri language filter (SiriProfanityFilter=false)."))
        L.addWidget(_row(TweakID.Siri2CallScreening,
            "Siri on Lock Screen", "Siri from any lock state (AssistantAllowedForAnyLockscreen)."))

        # ── Liquid Glass per-app ──────────────────────────────────────────────
        L.addWidget(_hdr("Liquid Glass — Per-App Extensions"))
        L.addWidget(_div())
        for tid, name, flag in [
            (TweakID.SolariumFFMessages,     "Messages",       "Messages.Solarium"),
            (TweakID.SolariumFFMaps,         "Maps",           "Maps.Solarium"),
            (TweakID.SolariumFFSafari,       "Safari",         "MobileSafari.Solarium"),
            (TweakID.SolariumFFSpotlight,    "Spotlight",      "Spotlight.Solarium"),
            (TweakID.SolariumFFControlCenter,"Control Centre", "ControlCenter.Solarium"),
            (TweakID.SolariumFFNotifications,"Notifications",  "UserNotificationsUI.Solarium"),
            (TweakID.SolariumFFWidgets,      "Widgets",        "WidgetKit.Solarium"),
            (TweakID.SolariumFFMusic,        "Music",          "Music.Solarium"),
            (TweakID.SolariumFFPodcasts,     "Podcasts",       "Podcasts.Solarium"),
            (TweakID.SolariumFFPhone,        "Phone",          "Phone.Solarium"),
            (TweakID.SolariumFFCalendar,     "Calendar",       "Calendar.Solarium"),
            (TweakID.SolariumFFReminders,    "Reminders",      "Reminders.Solarium"),
            (TweakID.SolariumFFNotes,        "Notes",          "Notes.Solarium"),
        ]:
            L.addWidget(_row(tid, f"Liquid Glass — {name}",
                f"Feature flag: {flag}"))

        # ── Liquid Glass fine-tuning ──────────────────────────────────────────
        L.addWidget(_hdr("Liquid Glass — Fine-Tuning"))
        L.addWidget(_div())
        L.addWidget(_row(TweakID.NoLiquidStatusBar,
            "Disable Glass Status Bar", "Remove glass from status bar (SBDisableGlassStatusBar)."))
        L.addWidget(_row(TweakID.NoLiquidNotifications,
            "Disable Glass Notifications", "Solid banners instead of glass (SBDisableGlassNotifications)."))
        L.addWidget(_row(TweakID.SolariumHighContrast,
            "High Contrast Glass", "Boost contrast on all glass layers (SolariumHighContrast)."))
        L.addWidget(_row(TweakID.SolariumForceLightTint,
            "Force Light Tint", "Always render glass with light tint (SolariumForceLightTint)."))
        L.addWidget(_row(TweakID.SolariumMaxBlur,
            "Maximum Blur Radius", "Max blur on all Liquid Glass surfaces (SolariumMaxBlur)."))

        # ── SpringBoard managed prefs ─────────────────────────────────────────
        L.addWidget(_hdr("SpringBoard — Managed Preferences"))
        L.addWidget(_div())
        L.addWidget(_row(TweakID.SBShowBatteryPercentageAlways,
            "Always Show Battery %", "Force battery % in status bar (SBUIForceDisplayBatteryPercentageNew)."))
        L.addWidget(_row(TweakID.SBHideHomeIndicator,
            "Hide Home Bar", "Remove home indicator (SBHideHomeIndicator)."))
        L.addWidget(_row(TweakID.SBDisableParallaxEffect,
            "Disable Parallax", "No icon/wallpaper parallax (SBDisableParallax)."))
        L.addWidget(_row(TweakID.SBAlwaysGlassHeaders,
            "Always Show Glass Headers", "Keep glass section headers visible (SBAlwaysShowGlassGroupHeaders)."))
        L.addWidget(_row(TweakID.SBExpandedDynamicIsland,
            "Persistent Expanded Dynamic Island", "Keep Dynamic Island expanded (SBEnableExpandedDynamicIslandPersistent)."))
        L.addWidget(_row(TweakID.SBAlwaysShowClockDI,
            "Clock with Dynamic Island", "Show clock alongside Dynamic Island (SBShowClockWithDynamicIsland)."))

        # ── Audio — Managed Preferences ───────────────────────────────────────
        L.addWidget(_hdr("Audio — Managed Preferences"))
        L.addWidget(_div())
        L.addWidget(_row(TweakID.AudioSoundEffectsEnabled,
            "System Sound Effects",
            "Force system sound effects on (SBSoundEffectsEnabled)."))
        L.addWidget(_row(TweakID.AudioHapticsSync,
            "Audio-Haptics Sync",
            "Synchronised audio+haptic patterns (SBAudioHapticsSyncEnabled)."))

        # ── Liquid Glass — Extended Apps ──────────────────────────────────────
        L.addWidget(_hdr("Liquid Glass — Extended Apps"))
        L.addWidget(_div())
        for tid, name, flag in [
            (TweakID.SolariumFFBooks,      "Books",       "Books.Solarium"),
            (TweakID.SolariumFFWeather,    "Weather",     "Weather.Solarium"),
            (TweakID.SolariumFFStocks,     "Stocks",      "Stocks.Solarium"),
            (TweakID.SolariumFFClock,      "Clock",       "Clock.Solarium"),
            (TweakID.SolariumFFCalculator, "Calculator",  "Calculator.Solarium"),
            (TweakID.SolariumFFCamera,     "Camera",      "Camera.Solarium"),
            (TweakID.SolariumFFFaceTime,   "FaceTime",    "FaceTime.Solarium"),
            (TweakID.SolariumFFHealth,     "Health",      "Health.Solarium"),
            (TweakID.SolariumFFWallet,     "Wallet",      "Wallet.Solarium"),
            (TweakID.SolariumFFSettings,   "Settings",    "Preferences.Solarium"),
            (TweakID.SolariumFFFiles,      "Files",       "Files.Solarium"),
            (TweakID.SolariumFFTranslate,  "Translate",   "Translate.Solarium"),
            (TweakID.SolariumFFFreeform,   "Freeform",    "Freeform.Solarium"),
            (TweakID.SolariumFFNews,       "News",        "News.Solarium"),
            (TweakID.SolariumFFContacts,   "Contacts",    "Contacts.Solarium"),
            (TweakID.SolariumFFFindMy,     "Find My",     "FindMy.Solarium"),
            (TweakID.SolariumFFTV,         "Apple TV",    "TV.Solarium"),
            (TweakID.SolariumFFVoiceMemos, "Voice Memos", "VoiceMemos.Solarium"),
            (TweakID.SolariumFFShortcuts,  "Shortcuts",   "Shortcuts.Solarium"),
        ]:
            L.addWidget(_row(tid, f"Liquid Glass — {name}",
                f"Feature flag: {flag}"))

        # ── System Core — Managed Preferences ────────────────────────────────
        L.addWidget(_hdr("✦ System Core — Managed Preferences"))
        L.addWidget(_div())
        L.addWidget(_row(TweakID.SysCoreProMotion,
            "ProMotion 120Hz Display",
            "Force ProMotion on all content (SBProMotionEnabled)."))
        L.addWidget(_row(TweakID.SysCoreAnimSpeed,
            "Faster Animations",
            "Lower drag coefficient for snappier transitions (UIAnimationDragCoefficient=0.35)."))
        L.addWidget(_row(TweakID.SysCoreMTLOverlay,
            "Metal Performance Overlay",
            "Real-time GPU/FPS overlay on screen (MTOverlayEnabled)."))
        L.addWidget(_row(TweakID.SysCoreHideCarrier,
            "Hide Carrier Text",
            "Remove carrier name from status bar (SBHideCarrierText)."))
        L.addWidget(_row(TweakID.SysCoreDevSettings,
            "Show Developer Settings",
            "Expose developer settings in preferences (SBShowDeveloperSettings)."))
        L.addWidget(_row(TweakID.SysCoreAlwaysAOD,
            "Always-On Display Override",
            "Force Always-On Display active (SBAlwaysOnDisplayEnabled)."))
        L.addWidget(_row(TweakID.SysCoreAutoRotate,
            "Force Auto-Rotate",
            "Ensure auto-rotation is never locked (SBDisableAutoRotation=false)."))

        # ── macOS-Style Dock & Navigation ─────────────────────────────────────
        L.addWidget(_hdr("⌘ macOS-Style Dock & Navigation"))
        L.addWidget(_div())
        L.addWidget(_row(TweakID.DockSolarium,
            "Liquid Glass Dock",
            "Enable Liquid Glass rendering for the Dock (Dock.Solarium)."))
        L.addWidget(_row(TweakID.DockHidden,
            "Auto-Hide Dock",
            "Force the Dock to remain hidden (SBForceDockHidden)."))
        L.addWidget(_row(TweakID.DockMagnification,
            "Dock Magnification",
            "Enable dock icon magnification on hover (SBDockMagnificationEnabled)."))
        L.addWidget(_row(TweakID.NavGestureSwipeBack,
            "Swipe-Back Navigation",
            "Re-enable back-swipe breadcrumb gesture (SBNeverBreadcrumb=false)."))
        L.addWidget(_row(TweakID.NavGestureLongPress,
            "Long-Press Home Menu",
            "Enable long-press contextual menu on Home button (SBLongPressHomeMenuEnabled)."))
        L.addWidget(_row(TweakID.NavGestureAssistiveTouch,
            "Assistive Touch Overlay",
            "Enable on-screen assistive touch button (SBAssistiveTouchEnabled)."))

        # ── Alien Color Engine ────────────────────────────────────────────────
        L.addWidget(_hdr("◈ Alien Color Engine — Accessibility"))
        L.addWidget(_div())
        L.addWidget(_row(TweakID.AlienSmartInvert,
            "Smart Invert Colors",
            "Invert UI colors but keep photos/video intact (AXSmartInvertColors)."))
        L.addWidget(_row(TweakID.AlienColorFilter,
            "Color Filter Mode",
            "Enable display color filter for alien visual effect (AXColorFilterEnabled)."))
        L.addWidget(_row(TweakID.AlienReduceTransparency,
            "Remove All Transparency",
            "Replace all translucency with solid colors — alien feel (AXReduceTransparency)."))
        L.addWidget(_row(TweakID.AlienDarkenColors,
            "Darken System Colors",
            "Shift all system colors darker for a deep alien palette (AXDarkenSystemColors)."))
        L.addWidget(_row(TweakID.AlienReduceMotion,
            "Remove All Motion",
            "Kill all animations — snap-cut transitions across the OS (AXReduceMotionEnabled)."))
        L.addWidget(_row(TweakID.AlienBoldText,
            "Bold All Text",
            "Force bold weight on every text element system-wide (AXBoldTextEnabled)."))
        L.addWidget(_row(TweakID.AlienHighContrast,
            "Maximum Contrast",
            "Push UI contrast to maximum — harsh, vivid, alien (AXIncreaseContrastEnabled)."))

        # ── maxregnerOS Sound Engine ───────────────────────────────────────────
        L.addWidget(_hdr("♪ maxregnerOS Sound Engine"))
        L.addWidget(_div())
        L.addWidget(_row(TweakID.SoundEngineBoostVolume,
            "Volume Boost",
            "Override volume limit for boosted output (SBVolumeBoostEnabled)."))
        L.addWidget(_row(TweakID.SoundEngineMuteSwitch,
            "Force Silent Mode",
            "Keep device in silent mode regardless of physical switch (SBSilentModeEnabled)."))
        L.addWidget(_row(TweakID.SoundEngineVibrateOnRing,
            "Vibrate on Ring",
            "Enable vibration when ringer is on (SBVibrateOnRing)."))
        L.addWidget(_row(TweakID.SoundEngineVibrateOnSilent,
            "Vibrate on Silent",
            "Enable vibration when device is silenced (SBVibrateOnSilent)."))
        L.addWidget(_row(TweakID.SoundEngineKeyClicks,
            "Keyboard Click Sounds",
            "Enable audible click for every key press (SBKeyClickEnabled)."))

        # ── Enhanced Siri v2 ──────────────────────────────────────────────────
        L.addWidget(_hdr("◎ Enhanced Siri — MDM Managed Preferences v2"))
        L.addWidget(_div())
        L.addWidget(_row(TweakID.SiriDictation,
            "Dictation",
            "Enable Siri dictation input (DictationEnabled)."))
        L.addWidget(_row(TweakID.SiriSearchEnabled,
            "Siri Search",
            "Enable Siri search integration system-wide (SearchEnabled)."))
        L.addWidget(_row(TweakID.SiriPersonalInsights,
            "Personal Insights",
            "Allow Siri to surface personal usage insights (PersonalInsights)."))
        L.addWidget(_row(TweakID.SiriContextSuggestions,
            "Contextual Suggestions",
            "Enable context-aware Siri suggestions (ContextualSuggestionsEnabled)."))
        L.addWidget(_row(TweakID.SiriOnDeviceOnly,
            "On-Device Only Mode",
            "Force all Siri processing to stay on device (OnDeviceOnlyEnabled)."))

    # ── callbacks ────────────────────────────────────────────────────────────

    def _enable_all(self):
        for tid in _page_tweak_ids:
            if tid in tweaks:
                tweaks[tid].set_enabled(True)
        self._sync_checkboxes()

    def _disable_all(self):
        for tid in _page_tweak_ids:
            if tid in tweaks:
                tweaks[tid].set_enabled(False)
        self._sync_checkboxes()

    def _maxregneros_mode(self):
        """Enable curated maxregnerOS signature set, disable rest."""
        for tid in _page_tweak_ids:
            if tid in tweaks:
                tweaks[tid].set_enabled(tid in MAXREGNEROS_MODE_IDS)
        self._sync_checkboxes()

    def _sync_checkboxes(self):
        for tid, chk in _checkbox_map.items():
            if tid in tweaks:
                chk.blockSignals(True)
                chk.setChecked(tweaks[tid].enabled)
                chk.blockSignals(False)

    def load_page(self):
        load_ios27()
        load_mros_solarium_extra()
        load_mros_real_prefs()
        load_mros_dock_nav()
        load_mros_alien_colors()
        load_mros_sound_engine()
        load_mros_siri_v2()
        self._sync_checkboxes()
