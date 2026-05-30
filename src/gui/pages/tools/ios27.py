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
    load_mros_home_screen, load_mros_display,
    load_mros_lock_screen, load_mros_keyboard,
    load_mros_notifications, load_mros_privacy_apps,
    load_mros_vision_alien, load_mros_deep_system, load_mros_coremotion,
    load_mros_ai_v2, load_mros_siri_ios27, load_mros_dynamic_island_ios27,
    load_mros_camera_ai, load_mros_satellite, load_mros_messages_health,
    _page_tweak_ids, MAXREGNEROS_MODE_IDS
)

# module-level checkbox registry — populated during _build_ui, synced in load_page
_checkbox_map: dict = {}

# ── visionOS × AlienOS colour palette (cycles per section) ───────────────────
_ACCENTS = [
    '#00ffcc',  # visionOS teal     — visionOS-AlienOS engine
    '#5eb8ff',  # sky blue          — Siri
    '#a8d8ff',  # glass blue        — Liquid Glass
    '#44ff88',  # alien green       — Home Screen
    '#ff66ff',  # alien magenta     — Icon Shapes
    '#ffd055',  # golden            — Display
    '#ff8855',  # orange            — Lock Screen
    '#44ffdd',  # alien cyan        — Keyboard
    '#ff55aa',  # alien pink        — Notifications
    '#aa88ff',  # lavender          — Control Center
    '#bb44ff',  # alien purple      — Privacy
    '#ff4455',  # danger red        — Deep System
    '#66ff44',  # acid green        — Alien Colors
    '#ff9944',  # amber             — Sound Engine
    '#88ccff',  # pastel sky        — Dock & Nav
    '#00ff88',  # alien lime        — CoreMotion
]
_sec_idx = [0]  # mutable so _hdr and _row can share it


# ── helpers ───────────────────────────────────────────────────────────────────

def _hdr(text: str) -> QFrame:
    accent = _ACCENTS[_sec_idx[0] % len(_ACCENTS)]
    _sec_idx[0] += 1
    card = QFrame()
    card.setStyleSheet(
        f"QFrame{{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,"
        f"stop:0 {accent}2a,stop:1 transparent);"
        f"border-left:3px solid {accent};border-radius:5px;margin-top:8px;}}"
    )
    lay = QHBoxLayout(card)
    lay.setContentsMargins(12, 7, 8, 7)
    lbl = QLabel(text)
    lbl.setStyleSheet(
        f"font-size:12px;font-weight:800;color:{accent};"
        f"letter-spacing:1.5px;background:transparent;border:none;"
    )
    lay.addWidget(lbl)
    lay.addStretch()
    return card


def _div() -> QWidget:
    w = QWidget()
    w.setFixedHeight(2)
    return w


def _row(tweak_id: TweakID, title: str, desc: str) -> QFrame:
    accent = _ACCENTS[(_sec_idx[0] - 1) % len(_ACCENTS)]
    card = QFrame()
    card.setObjectName("mrosRow")
    card.setStyleSheet(
        "QFrame#mrosRow{"
        "background:rgba(255,255,255,15);"
        "border-radius:10px;"
        "border:1px solid rgba(255,255,255,22);}"
        "QFrame#mrosRow:hover{"
        "background:rgba(255,255,255,28);"
        "border:1px solid rgba(255,255,255,50);}"
    )
    lay = QVBoxLayout(card)
    lay.setContentsMargins(14, 9, 14, 9)
    lay.setSpacing(3)
    chk = QCheckBox(title)
    chk.setStyleSheet(
        f"QCheckBox{{font-size:13px;font-weight:600;color:#e8f4ff;"
        f"spacing:9px;background:transparent;}}"
        f"QCheckBox::indicator{{width:17px;height:17px;border-radius:9px;"
        f"border:2px solid {accent};background:transparent;}}"
        f"QCheckBox::indicator:checked{{background:{accent};"
        f"border:2px solid {accent};}}"
    )
    chk.toggled.connect(lambda v, k=tweak_id: tweaks[k].set_enabled(v))
    _checkbox_map[tweak_id] = chk
    lay.addWidget(chk)
    lbl = QLabel(desc)
    lbl.setStyleSheet(
        "font-size:11px;color:#506070;padding-left:26px;"
        "background:transparent;border:none;"
    )
    lbl.setWordWrap(True)
    lay.addWidget(lbl)
    return card


def _btn(label: str, color: str, hover: str, pressed: str) -> QPushButton:
    b = QPushButton(label)
    b.setStyleSheet(
        f"QPushButton{{background:{color};color:#fff;border-radius:20px;"
        f"padding:6px 18px;font-size:12px;font-weight:800;"
        f"border:1px solid rgba(255,255,255,30);}}"
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

        # ── visionOS × AlienOS hero panel ────────────────────────────────────
        hero = QFrame()
        hero.setStyleSheet(
            "QFrame{background:qlineargradient(x1:0,y1:0,x2:1,y2:1,"
            "stop:0 #07192e,stop:0.45 #0b1e2d,stop:1 #080812);"
            "border-radius:18px;"
            "border:1px solid rgba(0,255,204,0.18);}"
        )
        hero_lay = QVBoxLayout(hero)
        hero_lay.setContentsMargins(22, 18, 22, 18)
        hero_lay.setSpacing(5)

        title_row = QHBoxLayout()
        title_row.setSpacing(12)
        brand_lbl = QLabel("mROS")
        brand_lbl.setStyleSheet(
            "font-size:38px;font-weight:900;"
            "color:qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            "stop:0 #00ffcc,stop:0.45 #5eb8ff,stop:1 #bb44ff);"
            "letter-spacing:7px;background:transparent;"
        )
        badge = QLabel("visionOS × AlienOS")
        badge.setStyleSheet(
            "font-size:10px;font-weight:700;color:#00ffcc;"
            "background:rgba(0,255,204,0.10);"
            "border:1px solid rgba(0,255,204,0.28);"
            "border-radius:5px;padding:3px 9px;background:transparent;"
        )
        title_row.addWidget(brand_lbl)
        title_row.addWidget(badge)
        title_row.addStretch()
        hero_lay.addLayout(title_row)

        sub_lbl = QLabel(
            "Deep System Control  ·  All Pre-Enabled  ·  No BookRestore  ·  maxregnerOS"
        )
        sub_lbl.setStyleSheet(
            "font-size:11px;color:#2a4a6a;letter-spacing:0.5px;background:transparent;"
        )
        hero_lay.addWidget(sub_lbl)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)
        b_all = _btn("⚡ Beast Mode",  "#0d3f7a", "#1a5fb4", "#082a52")
        b_on  = _btn("Enable All",     "#0d4f1a", "#1a7a2d", "#073512")
        b_off = _btn("Disable All",    "#2a2a3a", "#3a3a4a", "#1a1a2a")
        b_all.clicked.connect(self._maxregneros_mode)
        b_on.clicked.connect(self._enable_all)
        b_off.clicked.connect(self._disable_all)
        for b in (b_all, b_on, b_off):
            btn_row.addWidget(b)
        btn_row.addStretch()
        hero_lay.addLayout(btn_row)
        L.addWidget(hero)
        L.addSpacing(4)

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

        # ── Home Screen ───────────────────────────────────────────────────────
        L.addWidget(_hdr("Home Screen — Layout & Icons"))
        L.addWidget(_div())
        L.addWidget(_row(TweakID.HomeHideIconLabels,
            "Hide Icon Labels",
            "Remove text labels beneath all app icons (SBIconTextEnabled=false)."))
        L.addWidget(_row(TweakID.HomeHidePageDots,
            "Hide Page Indicator Dots",
            "Remove the dot row showing home screen pages (SBPageIndicatorEnabled=false)."))
        L.addWidget(_row(TweakID.HomeSearchBar,
            "Show Home Screen Search Bar",
            "Always-visible Spotlight search bar on home screen (SBShowHomeScreenSearchBar)."))
        L.addWidget(_row(TweakID.HomeAutoArrange,
            "Auto-Arrange Icons",
            "Automatically fill icon gaps like iPhone (SBAutoArrangeApps)."))
        L.addWidget(_row(TweakID.HomeLongPressMenu,
            "Long-Press Context Menu",
            "Show edit/share context menu on long-press (SBLongPressHomeScreenContextMenuEnabled)."))
        L.addWidget(_row(TweakID.HomeSwipeToUnlock,
            "Swipe-to-Unlock Gesture",
            "Enable classic swipe-to-unlock home gesture (SBSwipeToUnlockEnabled)."))
        L.addWidget(_row(TweakID.HomeFocusMode,
            "Focus Mode Integration",
            "Tie home screen layout to active Focus mode (SBHomeFocusModeEnabled)."))
        L.addWidget(_row(TweakID.HomeGridColumns,
            "5-Column Icon Grid",
            "Force 5 icon columns in portrait (SBIconColumnsPortrait=5)."))
        L.addWidget(_row(TweakID.HomeGridRows,
            "7-Row Icon Grid",
            "Force 7 icon rows in portrait — more apps visible (SBIconRowsPortrait=7)."))
        L.addWidget(_row(TweakID.HomeLargeIcons,
            "Large Icons Mode",
            "Increase icon size across the home screen (SBLargeIconsEnabled)."))

        # ── Icon Appearance ───────────────────────────────────────────────────
        L.addWidget(_hdr("Icon Appearance — Shapes & Colors"))
        L.addWidget(_div())
        L.addWidget(_row(TweakID.IconButtonShapes,
            "Button Shapes (Circle-Style Icons)",
            "Adds visible circular/rectangular outlines around all interactive icons (AXButtonShapesEnabled)."))
        L.addWidget(_row(TweakID.IconOnOffLabels,
            "On/Off Switch Labels",
            "Show I/O text labels on all toggle switches throughout the OS (AXOnOffSwitchLabels)."))
        L.addWidget(_row(TweakID.IconGrayscale,
            "Grayscale Icons",
            "Render entire UI and all icons in grayscale (AXGrayscaleEnabled)."))
        L.addWidget(_row(TweakID.IconReduceWhitePoint,
            "Reduce White Point",
            "Lower maximum brightness of white areas — easier on eyes (AXReduceWhitePoint)."))
        L.addWidget(_row(TweakID.IconDifferentiateColors,
            "Differentiate Without Color",
            "Add shapes/symbols instead of relying on color alone (AXDifferentiateWithoutColor)."))

        # ── Display & Visual ──────────────────────────────────────────────────
        L.addWidget(_hdr("Display & Visual — System Rendering"))
        L.addWidget(_div())
        L.addWidget(_row(TweakID.DisplayNightShift,
            "Night Shift Always On",
            "Force warm color temperature shift at all times (NightShiftEnabled)."))
        L.addWidget(_row(TweakID.DisplayTrueTone,
            "True Tone Always On",
            "Force adaptive True Tone color balance (TrueToneEnabled)."))
        L.addWidget(_row(TweakID.DisplayReduceFlicker,
            "Reduce Display Flicker",
            "Minimise 60Hz flicker on ProMotion panels (UIReduceFlickerEnabled)."))
        L.addWidget(_row(TweakID.DisplayEnhanceText,
            "Enhance Text Legibility",
            "Increase font weight throughout the UI for sharper text (UIEnhanceTextLegibility)."))
        L.addWidget(_row(TweakID.DisplayLargeText,
            "Accessibility XL Text Size",
            "Set system text to maximum accessibility size (UIPreferredContentSizeCategoryName)."))
        L.addWidget(_row(TweakID.DisplayCursorThick,
            "Thick Text Cursor",
            "Use a thicker insertion cursor in all text fields (AXCursorThicknessEnabled)."))
        L.addWidget(_row(TweakID.DisplayFlashAlerts,
            "Flash Screen for Alerts",
            "Flash the display instead of (or in addition to) sound for alerts (AXFlashScreenForAlerts)."))

        # ── Lock Screen ───────────────────────────────────────────────────────
        L.addWidget(_hdr("Lock Screen — Controls & Security"))
        L.addWidget(_div())
        L.addWidget(_row(TweakID.LockShowDate,
            "Show Date on Lock Screen",
            "Always display date below the clock (SBLockScreenShowDate)."))
        L.addWidget(_row(TweakID.LockNotifPreview,
            "Show Notification Previews",
            "Show notification content on the lock screen (SBLockScreenShowNotificationPreview)."))
        L.addWidget(_row(TweakID.LockShowMediaControls,
            "Show Media Controls",
            "Display playback controls on the lock screen (SBLockScreenShowMediaControls)."))
        L.addWidget(_row(TweakID.LockShowCamera,
            "Show Camera Shortcut",
            "Show camera quick-launch button on lock screen (SBLockScreenShowCameraButton)."))
        L.addWidget(_row(TweakID.LockShowFlashlight,
            "Show Flashlight Shortcut",
            "Show flashlight button on lock screen (SBLockScreenShowFlashlightButton)."))
        L.addWidget(_row(TweakID.LockBiometricOnWake,
            "Face ID on Wake",
            "Automatically attempt Face ID when screen wakes (SBFaceIDOnWake)."))
        L.addWidget(_row(TweakID.LockRequirePasscodeImmediately,
            "Require Passcode Immediately",
            "Demand passcode the instant the screen locks (SBRequirePasscodeImmediately)."))
        L.addWidget(_row(TweakID.LockEnableUsb,
            "Disable USB Restricted Mode",
            "Allow USB accessories even after 1 hour locked (SBUSBRestrictedModeDisabled)."))

        # ── Keyboard ──────────────────────────────────────────────────────────
        L.addWidget(_hdr("Keyboard — Input Preferences"))
        L.addWidget(_div())
        L.addWidget(_row(TweakID.KbAutoCorrect,
            "Auto-Correct",
            "Enable automatic spelling correction while typing (KeyboardAutocorrection)."))
        L.addWidget(_row(TweakID.KbAutoCapitalize,
            "Auto-Capitalise",
            "Automatically capitalise the first letter of sentences (KeyboardAutocapitalization)."))
        L.addWidget(_row(TweakID.KbPredictive,
            "Predictive Text",
            "Show QuickType word suggestions above the keyboard (KeyboardPrediction)."))
        L.addWidget(_row(TweakID.KbHaptics,
            "Keyboard Haptics",
            "Tactile feedback on every key press (KeyboardHapticsEnabled)."))
        L.addWidget(_row(TweakID.KbSwipeTyping,
            "Swipe / Slide to Type",
            "Enable swipe-gesture typing across the keyboard (KeyboardSlideToType)."))
        L.addWidget(_row(TweakID.KbSmartPunctuation,
            "Smart Punctuation",
            "Auto-convert quotes and dashes to typographic versions (KeyboardSmartPunctuation)."))
        L.addWidget(_row(TweakID.KbDictation,
            "Keyboard Dictation",
            "Enable microphone dictation from the keyboard (KeyboardDictation)."))
        L.addWidget(_row(TweakID.KbEmojiSuggestions,
            "Emoji Suggestions",
            "Show emoji replacements in the predictive bar (KeyboardEmojiSuggestions)."))
        L.addWidget(_row(TweakID.KbInlinePredictions,
            "Inline Predictions",
            "Show ghost-text completions inline as you type (KeyboardInlinePredictions)."))

        # ── Notifications & Control Center ────────────────────────────────────
        L.addWidget(_hdr("Notifications & Control Center"))
        L.addWidget(_div())
        L.addWidget(_row(TweakID.NotifBadges,
            "App Badge Numbers",
            "Show numeric badges on app icons for unread counts (BadgesEnabled)."))
        L.addWidget(_row(TweakID.NotifSounds,
            "Notification Sounds",
            "Play sound for all incoming notifications (SoundsEnabled)."))
        L.addWidget(_row(TweakID.NotifVibrations,
            "Notification Vibrations",
            "Vibrate for all incoming notifications (VibrationsEnabled)."))
        L.addWidget(_row(TweakID.NotifPreviewAlways,
            "Always Show Notification Previews",
            "Show message content in banners regardless of lock state (PreviewsAlways)."))
        L.addWidget(_row(TweakID.NotifGroupByApp,
            "Group Notifications by App",
            "Collapse multiple notifications per app into a stack (GroupingByApp)."))
        L.addWidget(_row(TweakID.NotifPersistentAlerts,
            "Persistent Alert Style",
            "Banners stay on screen until manually dismissed (AlertTypePersistent)."))
        L.addWidget(_row(TweakID.NotifCriticalAlerts,
            "Critical Alerts Enabled",
            "Allow critical priority alerts that bypass Do Not Disturb (CriticalAlertsEnabled)."))
        L.addWidget(_row(TweakID.NotifAnnounce,
            "Announce Notifications via Siri",
            "Have Siri read out notifications through AirPods (AnnounceNotificationsEnabled)."))
        L.addWidget(_hdr("  Control Center Toggles"))
        L.addWidget(_row(TweakID.CCAlwaysShow,
            "Always Show Control Center",
            "Show CC swipe handle on every screen including apps (SBCCAlwaysShow)."))
        L.addWidget(_row(TweakID.CCShowInApps,
            "Control Center in Apps",
            "Allow CC to open while an app is in the foreground (SBCCShowInApps)."))
        L.addWidget(_row(TweakID.CCLockRotationToggle,
            "Rotation Lock Toggle",
            "Include rotation lock in Control Center (SBCCLockRotationEnabled)."))
        L.addWidget(_row(TweakID.CCNightShiftToggle,
            "Night Shift Toggle",
            "Add Night Shift quick toggle to Control Center (SBCCNightShiftEnabled)."))
        L.addWidget(_row(TweakID.CCLowPowerToggle,
            "Low Power Mode Toggle",
            "Add Low Power Mode switch to Control Center (SBCCLowPowerEnabled)."))
        L.addWidget(_row(TweakID.CCMirroringToggle,
            "AirPlay / Mirroring Toggle",
            "Add AirPlay mirroring shortcut to Control Center (SBCCAirPlayEnabled)."))
        L.addWidget(_row(TweakID.CCHideBrightness,
            "Hide Brightness Slider",
            "Remove brightness control from Control Center (SBCCHideBrightness)."))
        L.addWidget(_row(TweakID.CCHideVolume,
            "Hide Volume Slider",
            "Remove volume control from Control Center (SBCCHideVolume)."))
        L.addWidget(_row(TweakID.CCHideWifi,
            "Hide Wi-Fi Toggle",
            "Remove Wi-Fi button from Control Center (SBCCHideWifi)."))
        L.addWidget(_row(TweakID.CCHideBluetooth,
            "Hide Bluetooth Toggle",
            "Remove Bluetooth button from Control Center (SBCCHideBluetooth)."))

        # ── Privacy & App Store ───────────────────────────────────────────────
        L.addWidget(_hdr("Privacy, Analytics & App Store"))
        L.addWidget(_div())
        L.addWidget(_row(TweakID.PrivacyAnalytics,
            "Allow Diagnostic Submission",
            "Allow iOS to send crash reports and analytics to Apple (allowDiagnosticSubmission)."))
        L.addWidget(_row(TweakID.PrivacyPersonalizedAds,
            "Allow Personalised Ads",
            "Let Apple use your data for targeted advertising (allowApplePersonalizedAdvertising)."))
        L.addWidget(_row(TweakID.PrivacyImproveHealth,
            "Allow Health Data Sharing",
            "Share Health data with researchers and Apple (allowHealthDataSharing)."))
        L.addWidget(_row(TweakID.PrivacyShareiCloud,
            "Allow Managed App iCloud Sync",
            "Permit managed apps to sync data through iCloud (allowManagedAppsCloudSync)."))
        L.addWidget(_row(TweakID.PrivacyActivityContinuation,
            "Allow Handoff / Activity Continuation",
            "Enable Handoff between Apple devices (allowActivityContinuation)."))
        L.addWidget(_row(TweakID.AppAutoUpdates,
            "Automatic App Updates",
            "Download and install app updates in background (AutomaticAppUpdateEnabled)."))
        L.addWidget(_row(TweakID.AppAutoDownloads,
            "Automatic App Downloads",
            "Auto-download apps purchased on other devices (AutomaticDownloadEnabled)."))
        L.addWidget(_row(TweakID.AppOffloadUnused,
            "Offload Unused Apps",
            "Remove rarely-used apps but keep their data (OffloadUnusedAppsEnabled)."))
        L.addWidget(_row(TweakID.AppInAppPurchases,
            "Allow In-App Purchases",
            "Permit purchases inside apps (InAppPurchasesEnabled)."))
        L.addWidget(_row(TweakID.AppRatingsPrompt,
            "Disable Ratings Prompts",
            "Block apps from asking you to rate them (DisableAppRatingsPrompt)."))

        # ── visionOS × AlienOS Visual Engine ─────────────────────────────────
        L.addWidget(_hdr("visionOS × AlienOS — Visual Engine"))
        L.addWidget(_row(TweakID.VisionDepthWallpaper,
            "Wallpaper Depth Effect",
            "Enable 3D parallax depth on the wallpaper layer (SBWallpaperDepthEffect)."))
        L.addWidget(_row(TweakID.VisionImmersiveBlur,
            "Immersive Blur Mode",
            "Apply full-screen immersive blur behind active UI sheets (SBImmersiveBlurEnabled)."))
        L.addWidget(_row(TweakID.VisionSpatialAudio,
            "Spatial Audio System-Wide",
            "Enable spatial / head-tracked audio for all output (SBAudioSpatialEnabled)."))
        L.addWidget(_row(TweakID.VisionLayeredUI,
            "Layered Interface (visionOS-style stacking)",
            "Render UI elements in layered z-depth stacks like visionOS (SBLayeredInterfaceEnabled)."))
        L.addWidget(_row(TweakID.VisionDepthBlur,
            "Depth-of-Field Blur",
            "Background elements blur with depth-of-field bokeh (SBDepthBlurEnabled)."))
        L.addWidget(_row(TweakID.VisionFullscreenApp,
            "True Full-Screen Apps",
            "Allow apps to occupy the full display edge-to-edge (SBFullScreenAppEnabled)."))
        L.addWidget(_row(TweakID.VisionFocusedAppShadow,
            "Focused App Drop Shadow",
            "Show visionOS-style floating shadow under the active app (SBFocusedAppShadowEnabled)."))
        L.addWidget(_row(TweakID.VisionWindowCornerRadius,
            "Rounded Window Corners",
            "Force extra-rounded corners on all app windows (SBWindowCornerRadiusEnabled)."))
        L.addWidget(_row(TweakID.VisionEnvironmentLighting,
            "Environment Lighting Response",
            "UI tint adapts to ambient light colour like visionOS (SBEnvironmentLightingEnabled)."))
        L.addWidget(_hdr("AlienOS — Colour Engine Extended"))
        L.addWidget(_row(TweakID.AlienColorFilterType,
            "Alien Colour Filter (Trichromacy Shift)",
            "Shift display colour channels for an alien-spectrum look — AXColorFilterType=1 (trichromacy)."))
        L.addWidget(_row(TweakID.AlienColorIntensity,
            "Alien Colour Intensity — Max",
            "Push colour filter to full intensity (AXColorFilterIntensity=1.0)."))
        L.addWidget(_row(TweakID.AlienClassicInvert,
            "Classic Colour Invert",
            "Invert every pixel on the display — the original alien look (AXInvertColors)."))
        L.addWidget(_row(TweakID.AlienPurpleSaturation,
            "Hyper-Saturation Mode",
            "Boost colour saturation across all system UI (AXIncreaseSaturationEnabled)."))
        L.addWidget(_row(TweakID.AlienVibrantMode,
            "Vibrant Overlay Mode",
            "Force maximum vibrancy on translucent surfaces (SBVibrantModeEnabled)."))
        L.addWidget(_row(TweakID.AlienNeonGlow,
            "Neon Glow UI Accents",
            "Add neon glow highlights to interactive UI elements (SBNeonGlowEnabled)."))

        # ── Deep System Core ──────────────────────────────────────────────────
        L.addWidget(_hdr("Deep System Core — Low-Level Overrides"))
        L.addWidget(_row(TweakID.DeepBackgroundRefresh,
            "Background App Refresh",
            "Allow all apps to refresh content in the background (SBBackgroundAppRefreshEnabled)."))
        L.addWidget(_row(TweakID.DeepPerformanceMode,
            "Performance Mode",
            "Force the SoC into sustained maximum performance state (SBPerformanceModeEnabled)."))
        L.addWidget(_row(TweakID.DeepPowerNap,
            "Power Nap",
            "Device fetches mail and updates silently while locked (SBPowerNapEnabled)."))
        L.addWidget(_row(TweakID.DeepLowMemoryWarnings,
            "Low Memory Warnings",
            "Show system low-memory alerts to diagnose RAM pressure (SBLowMemoryWarningEnabled)."))
        L.addWidget(_row(TweakID.DeepUIReduceMotion,
            "Disable UIKit Reduce Motion",
            "Force full animations — override UIReduceMotion (UIReduceMotionEnabled=false)."))
        L.addWidget(_row(TweakID.DeepForceTouch,
            "Force Touch / Haptic Touch",
            "Enable force-touch pressure sensitivity globally (SBForceTouchEnabled)."))
        L.addWidget(_row(TweakID.DeepAirDropEveryone,
            "AirDrop — Receive from Everyone",
            "Set AirDrop to accept transfers from all devices (SBAirDropReceivingMode=2)."))
        L.addWidget(_row(TweakID.DeepHandoff,
            "Handoff / Continuity",
            "Transfer tasks seamlessly between Apple devices (SBHandoffEnabled)."))
        L.addWidget(_row(TweakID.DeepUniversalControl,
            "Universal Control",
            "Control iPad/Mac with this iPhone's input (SBUniversalControlEnabled)."))
        L.addWidget(_row(TweakID.DeepContinuityCamera,
            "Continuity Camera",
            "Use iPhone as a webcam for Mac via USB/Wi-Fi (SBContinuityCameraEnabled)."))
        L.addWidget(_row(TweakID.DeepFindMyNetwork,
            "Find My Network",
            "Broadcast Bluetooth beacon for Find My even when off (SBFindMyNetworkEnabled)."))
        L.addWidget(_row(TweakID.DeepCarPlay,
            "CarPlay Support",
            "Enable CarPlay connection support (SBCarPlayEnabled)."))
        L.addWidget(_row(TweakID.DeepFocusStatusShare,
            "Share Focus Status",
            "Let contacts see when you have a Focus active (SBFocusStatusShareEnabled)."))
        L.addWidget(_row(TweakID.DeepPersonalHotspot,
            "Personal Hotspot",
            "Enable Wi-Fi / USB hotspot sharing (SBPersonalHotspotEnabled)."))
        L.addWidget(_row(TweakID.DeepSiriSuggestions,
            "Siri Suggestions System-Wide",
            "Siri proactively suggests apps, contacts, shortcuts (SBSiriSuggestionsEnabled)."))
        L.addWidget(_row(TweakID.DeepCrashReporterDisable,
            "Disable Crash Reporter",
            "Suppress all crash dialogs and auto-reports (SBCrashReporterDisabled)."))
        L.addWidget(_row(TweakID.DeepAnalyticsDisable,
            "Disable System Diagnostics",
            "Block all telemetry and diagnostic data collection (SBDiagnosticsDisabled)."))

        # ── CoreMotion — Sensor Engine ────────────────────────────────────────
        L.addWidget(_hdr("CoreMotion — Sensor Engine"))
        L.addWidget(_row(TweakID.MotionGyroscope,
            "Gyroscope",
            "Enable the three-axis gyroscope sensor (GyroscopeEnabled)."))
        L.addWidget(_row(TweakID.MotionAccelerometer,
            "Accelerometer",
            "Enable the 3-axis linear acceleration sensor (AccelerometerEnabled)."))
        L.addWidget(_row(TweakID.MotionPedometer,
            "Pedometer / Step Counter",
            "Enable step counting and distance tracking (PedometerEnabled)."))
        L.addWidget(_row(TweakID.MotionAltimeter,
            "Barometric Altimeter",
            "Enable atmospheric pressure sensor for elevation (AltimeterEnabled)."))
        L.addWidget(_row(TweakID.MotionDeviceMotion,
            "Device Motion Fusion",
            "Enable combined gyro + accel + magnetometer fusion output (DeviceMotionEnabled)."))
        L.addWidget(_row(TweakID.MotionMagnetometer,
            "Magnetometer / Compass",
            "Enable magnetic field sensor used by Maps compass (MagnetometerEnabled)."))
        L.addWidget(_row(TweakID.MotionActivityRecognition,
            "Activity Recognition (Walk/Run/Drive)",
            "Enable ML-based activity classification from motion data (ActivityRecognitionEnabled)."))

        # ── Apple Intelligence v2 (iOS 27) ────────────────────────────────────
        L.addWidget(_hdr("Apple Intelligence v2 — iOS 27 AI Engine"))
        L.addWidget(_row(TweakID.AIv2WritingTools,
            "Writing Tools",
            "AI grammar correction, tone adjustment and full rewrites system-wide (WritingToolsEnabled)."))
        L.addWidget(_row(TweakID.AIv2Genmoji,
            "Genmoji — AI Emoji Generation",
            "Generate custom emoji from text descriptions via Apple Intelligence (GenmojiEnabled)."))
        L.addWidget(_row(TweakID.AIv2ImagePlayground,
            "Image Playground",
            "Create AI-generated images in Messages, Notes and apps (ImagePlaygroundEnabled)."))
        L.addWidget(_row(TweakID.AIv2NotifSummaries,
            "Notification Summaries",
            "AI summarises stacked notifications into one-line digests (NotificationSummariesEnabled)."))
        L.addWidget(_row(TweakID.AIv2PriorityNotif,
            "Priority Notifications",
            "Apple Intelligence surfaces time-sensitive notifications at the top (PriorityNotificationsEnabled)."))
        L.addWidget(_row(TweakID.AIv2SmartReply,
            "Smart Reply Suggestions",
            "AI-generated quick-reply options in Messages and Mail (SmartReplyEnabled)."))
        L.addWidget(_row(TweakID.AIv2Proofread,
            "Proofread Mode",
            "Inline grammar and style suggestions as you type (ProofreadEnabled)."))
        L.addWidget(_row(TweakID.AIv2Rewrite,
            "Rewrite / Tone Shift",
            "Rewrite selected text in Friendly, Professional or Concise tone (RewriteEnabled)."))
        L.addWidget(_row(TweakID.AIv2NLShortcuts,
            "Natural Language Shortcuts",
            "Create Shortcuts by describing them in plain language — no blocks needed (NaturalLanguageShortcutsEnabled)."))
        L.addWidget(_row(TweakID.AIv2ThirdPartyAI,
            "Third-Party AI Integration (ChatGPT / Gemini / Claude)",
            "Route AI requests to ChatGPT, Google Gemini, or Claude as default (ThirdPartyAIIntegrationEnabled)."))
        L.addWidget(_row(TweakID.AIv2PersonalContext,
            "Personal Context Awareness",
            "Siri reads your calendar, emails and messages for context (PersonalContextEnabled)."))
        L.addWidget(_row(TweakID.AIv2MemoryEnabled,
            "AI Memory Across Conversations",
            "Siri remembers preferences and past requests persistently (MemoryEnabled)."))
        L.addWidget(_row(TweakID.AIv2ScreenAwareness,
            "Siri Screen Awareness",
            "Siri understands what is on screen and acts on it (ScreenAwarenessEnabled)."))
        L.addWidget(_row(TweakID.AIv2InAppActions,
            "Siri In-App Actions",
            "Siri performs multi-step actions inside third-party apps (InAppActionsEnabled)."))
        L.addWidget(_hdr("  Photos AI Editing (iOS 27)"))
        L.addWidget(_row(TweakID.AIv2PhotoExtend,
            "Extend — Generate Beyond the Frame",
            "AI fills in scenery outside the original photo boundary (PhotoExtendEnabled)."))
        L.addWidget(_row(TweakID.AIv2PhotoEnhance,
            "Enhance — AI Quality Boost",
            "Automatically improve colour, lighting and sharpness with AI (PhotoEnhanceEnabled)."))
        L.addWidget(_row(TweakID.AIv2PhotoReframe,
            "Reframe — Shift Perspective",
            "Recompose spatial photos from a different angle post-capture (PhotoReframeEnabled)."))
        L.addWidget(_row(TweakID.AIv2PhotoCleanUp,
            "Clean Up — Remove Objects",
            "Intelligently remove unwanted people and objects from photos (PhotoCleanUpEnabled)."))

        # ── Siri iOS 27 Redesign ──────────────────────────────────────────────
        L.addWidget(_hdr("Siri iOS 27 — Redesigned AI Assistant"))
        L.addWidget(_row(TweakID.SiriStandaloneApp,
            "Siri Standalone App",
            "Enable the new dedicated Siri app introduced in iOS 27 (SBSiriStandaloneAppEnabled)."))
        L.addWidget(_row(TweakID.SiriDIIntegration,
            "Siri in Dynamic Island",
            "Deep Siri integration with animated pill-shaped Dynamic Island overlay (SBSiriDynamicIslandEnabled)."))
        L.addWidget(_row(TweakID.SiriSplitIsland,
            "Split Island — Dual Bubbles",
            "Dynamic Island separates into two floating bubbles for Siri + background activity (SBSiriSplitIslandEnabled)."))
        L.addWidget(_row(TweakID.SiriChatInterface,
            "Chatbot-Style Chat Interface",
            "New ChatGPT-like persistent conversation interface for Siri (ChatInterfaceEnabled)."))
        L.addWidget(_row(TweakID.SiriMultiStep,
            "Multi-Step Actions",
            "Siri chains actions across multiple apps in one request (MultiStepActionsEnabled)."))
        L.addWidget(_row(TweakID.SiriSearchOrAsk,
            "Search or Ask — Swipe Down",
            "Swipe down from top-centre anywhere in iOS to invoke keyboard Siri (SBSearchOrAskEnabled)."))
        L.addWidget(_row(TweakID.SiriThirdPartyAI,
            "Third-Party AI as Siri Backend",
            "Use ChatGPT, Gemini, or Claude to power Siri responses (ThirdPartyAIEnabled)."))
        L.addWidget(_row(TweakID.SiriDarkTheme,
            "Siri Dark Theme (iOS 27 style)",
            "Enable the all-dark Siri UI with pink/purple/orange accents (SBSiriDarkThemeEnabled)."))
        L.addWidget(_row(TweakID.SiriProCamera,
            "Siri Camera Mode",
            "Dedicated Siri mode in the Camera app for visual queries and scanning (SiriCameraModeEnabled)."))

        # ── Dynamic Island iOS 27 + Live Activities ───────────────────────────
        L.addWidget(_hdr("Dynamic Island iOS 27 — Smart Island & Live Activities"))
        L.addWidget(_row(TweakID.DISplitBubbles,
            "Split Island (Two Simultaneous Activities)",
            "Dynamic Island divides into two separate floating bubbles (SBDISplitBubblesEnabled)."))
        L.addWidget(_row(TweakID.DICustomizeContent,
            "Customise Island Content",
            "Choose which activities and apps appear in the Dynamic Island (SBDICustomizeContentEnabled)."))
        L.addWidget(_row(TweakID.DILiveResultPanels,
            "Live Result Panels",
            "Siri shows rich, interactive result cards expanding from the island (SBDILiveResultPanelsEnabled)."))
        L.addWidget(_row(TweakID.DISearchingIndicator,
            "Searching Glow Indicator",
            "Animated glowing dot in the island while Siri searches (SBDISearchingIndicatorEnabled)."))
        L.addWidget(_row(TweakID.DIExpandedDefault,
            "Island Expanded by Default",
            "Dynamic Island stays expanded showing content without tapping (SBDIExpandedByDefault)."))
        L.addWidget(_row(TweakID.DIMultiActivity,
            "Multi-Activity Support",
            "Run multiple Live Activities simultaneously on the island (SBDIMultiActivityEnabled)."))
        L.addWidget(_hdr("  Live Activities"))
        L.addWidget(_row(TweakID.LiveActivities,
            "Live Activities Enabled",
            "Allow apps to display real-time updating widgets on the island and lock screen (SBLiveActivitiesEnabled)."))
        L.addWidget(_row(TweakID.LiveActivitiesLockScreen,
            "Live Activities on Lock Screen",
            "Show persistent Live Activity banners on the lock screen (SBLiveActivitiesOnLockScreen)."))
        L.addWidget(_row(TweakID.LiveActivitiesStandBy,
            "Live Activities in StandBy",
            "Display Live Activities in full-screen StandBy mode (SBLiveActivitiesInStandBy)."))
        L.addWidget(_row(TweakID.LiveActivitiesAlwaysShow,
            "Always Show Live Activities",
            "Never auto-hide Live Activities from the island or lock screen (SBLiveActivitiesAlwaysShow)."))
        L.addWidget(_hdr("  StandBy Mode"))
        L.addWidget(_row(TweakID.StandByEnabled,
            "StandBy Enabled",
            "Activate full-screen dock display when iPhone is charging on its side (SBStandByEnabled)."))
        L.addWidget(_row(TweakID.StandByAlwaysOn,
            "StandBy Always On",
            "Keep StandBy display active without the screen dimming (SBStandByAlwaysOn)."))
        L.addWidget(_row(TweakID.StandByNightMode,
            "StandBy Night Mode",
            "Switch to red-tinted display automatically in dark environments (SBStandByNightMode)."))
        L.addWidget(_row(TweakID.StandBySmartRotation,
            "Smart Rotation in StandBy",
            "Auto-rotate between clock, photos and widgets based on context (SBStandBySmartRotation)."))
        L.addWidget(_row(TweakID.StandByWidgets,
            "StandBy Widgets",
            "Show interactive widget panels in StandBy mode (SBStandByWidgetsEnabled)."))
        L.addWidget(_row(TweakID.StandByPhotoShuffle,
            "StandBy Photo Shuffle",
            "Cycle through your photo library as a live frame in StandBy (SBStandByPhotoShuffleEnabled)."))
        L.addWidget(_row(TweakID.StandByShowClock,
            "Always Show Clock in StandBy",
            "Keep the large clock visible at all times in StandBy (SBStandByShowClock)."))

        # ── Camera & Visual Intelligence ──────────────────────────────────────
        L.addWidget(_hdr("Camera & Visual Intelligence — iOS 27"))
        L.addWidget(_row(TweakID.CameraSiriMode,
            "Camera Siri Mode (iOS 27 — new tab)",
            "New Siri tab in Camera for querying and scanning with AI (SiriModeEnabled)."))
        L.addWidget(_row(TweakID.CameraVisualIntelligence,
            "Visual Intelligence",
            "Point camera at anything to instantly search, translate or identify it (VisualIntelligenceEnabled)."))
        L.addWidget(_row(TweakID.CameraNutritionScan,
            "Nutrition Label Scanning → Health",
            "Scan food packaging to auto-log calories and macros to the Health app (NutritionLabelScanEnabled)."))
        L.addWidget(_row(TweakID.CameraContactScan,
            "Contact Card Scanning",
            "Scan business cards to extract and save contact information (ContactCardScanEnabled)."))
        L.addWidget(_row(TweakID.CameraPhotographicStyles,
            "Photographic Styles",
            "Apply persistent AI-driven colour and tone styles to every photo (PhotographicStylesEnabled)."))
        L.addWidget(_row(TweakID.CameraProRes,
            "ProRes Video Recording",
            "Record in Apple ProRes format for professional post-production (ProResVideoEnabled)."))
        L.addWidget(_row(TweakID.CameraAppleLog,
            "Apple Log — Log Gamma Video",
            "Shoot in Apple Log colour science for maximum grading headroom (AppleLogEnabled)."))
        L.addWidget(_row(TweakID.CameraActionMode,
            "Action Mode — Stabilisation",
            "Ultra-stable Action Mode for sports and movement (ActionModeEnabled)."))
        L.addWidget(_row(TweakID.CameraWidgetControl,
            "Customisable Camera Widget Controls",
            "Choose which controls appear in Camera widget / Control Center shortcut (WidgetControlCustomizationEnabled)."))
        L.addWidget(_row(TweakID.CameraAdaptiveSensor,
            "Adaptive Sensor Processing",
            "Dynamically switch between sensor modes for optimal capture (AdaptiveSensorEnabled)."))

        # ── Satellite Connectivity ────────────────────────────────────────────
        L.addWidget(_hdr("Satellite Connectivity — iOS 27 / C2 Modem (5G NR-NTN)"))
        L.addWidget(_row(TweakID.SatelliteSOSEnabled,
            "Emergency SOS via Satellite",
            "Send distress signals when there is no cellular coverage (EmergencySOSEnabled)."))
        L.addWidget(_row(TweakID.SatelliteMapsEnabled,
            "Apple Maps via Satellite",
            "Use Apple Maps navigation over satellite when data is unavailable (MapsEnabled)."))
        L.addWidget(_row(TweakID.SatellitePhotoMsg,
            "Send Photos via Satellite",
            "Attach and send photos through satellite messaging (PhotoMessagingEnabled)."))
        L.addWidget(_row(TweakID.SatelliteThirdPartyApps,
            "Third-Party App Satellite Access",
            "Allow third-party apps to use the satellite data connection (ThirdPartyAppAccessEnabled)."))
        L.addWidget(_row(TweakID.SatelliteAutoHandoff,
            "Automatic Cellular ↔ Satellite Handoff",
            "Seamlessly switch between cellular and satellite without interruption (AutomaticHandoffEnabled)."))
        L.addWidget(_row(TweakID.Satellite5GNR,
            "5G NR-NTN Standard (C2 Modem)",
            "Enable the 5G Non-Terrestrial Network standard for high-speed satellite (FiveGNRNTNEnabled)."))

        # ── iMessage iOS 27 ───────────────────────────────────────────────────
        L.addWidget(_hdr("iMessage iOS 27 — RCS, AI Replies & Satellite"))
        L.addWidget(_row(TweakID.MsgiMessageEnabled,
            "iMessage Enabled",
            "Use iMessage (blue bubbles) over data when available (iMessageEnabled)."))
        L.addWidget(_row(TweakID.MsgRCSEnabled,
            "RCS Messaging",
            "Rich Communication Services — high-res media, read receipts over SMS (RCSEnabled)."))
        L.addWidget(_row(TweakID.MsgReadReceipts,
            "Read Receipts",
            "Show when the recipient has read your message (ReadReceiptsEnabled)."))
        L.addWidget(_row(TweakID.MsgAISmartReply,
            "AI Smart Reply",
            "Apple Intelligence generates context-aware quick-reply suggestions (AISmartReplyEnabled)."))
        L.addWidget(_row(TweakID.MsgFilterUnknown,
            "Filter Unknown Senders",
            "Automatically separate messages from unknown contacts (FilterUnknownSendersEnabled)."))
        L.addWidget(_row(TweakID.MsgFallbackSMS,
            "Fallback to SMS/MMS",
            "Send as SMS when iMessage is unavailable (FallbackToSMSEnabled)."))
        L.addWidget(_row(TweakID.MsgShareNamePhoto,
            "Share Name and Photo",
            "Auto-share your contact name and photo when messaging (ShareNameAndPhotoEnabled)."))
        L.addWidget(_row(TweakID.MsgSatellite,
            "Satellite Messaging (iOS 27)",
            "Send and receive iMessages over satellite when off-grid (SatelliteMessagingEnabled)."))

        # ── Health iOS 27 ─────────────────────────────────────────────────────
        L.addWidget(_hdr("Health iOS 27 — AI Nutrition, Mental Wellbeing & More"))
        L.addWidget(_row(TweakID.HealthNutritionLogging,
            "Nutrition Logging via Camera",
            "Scan food labels with Visual Intelligence to auto-log to Health (NutritionLoggingEnabled)."))
        L.addWidget(_row(TweakID.HealthMentalWellbeing,
            "Mental Wellbeing Tracking",
            "Log daily mood, anxiety levels and emotional state (MentalWellbeingEnabled)."))
        L.addWidget(_row(TweakID.HealthCycleTracking,
            "Cycle Tracking",
            "Track menstrual cycle with period, ovulation and symptom logging (CycleTrackingEnabled)."))
        L.addWidget(_row(TweakID.HealthMedications,
            "Medications Tracking",
            "Log, schedule and get reminders for medications (MedicationsEnabled)."))
        L.addWidget(_row(TweakID.HealthVitalsTrends,
            "Vitals Trends & Notifications",
            "AI detects unusual patterns in heart rate, sleep and more (VitalsTrendsEnabled)."))
        L.addWidget(_row(TweakID.HealthDataSharing,
            "Health Data Sharing",
            "Share your health summary with a care provider or family (HealthSharingEnabled)."))
        L.addWidget(_row(TweakID.HealthFitnessSuggestions,
            "AI Fitness Suggestions",
            "Get personalised workout and activity suggestions based on your trends (FitnessSuggestionsEnabled)."))

        # ── Wallet iOS 27 ─────────────────────────────────────────────────────
        L.addWidget(_hdr("Wallet iOS 27 — Create a Pass, ID & Transit"))
        L.addWidget(_row(TweakID.WalletCreatePass,
            "Create a Pass (scan physical → digital)",
            "Scan any physical ticket or membership card to create a digital pass (CreatePassEnabled)."))
        L.addWidget(_row(TweakID.WalletAIEnabled,
            "Apple Intelligence in Wallet",
            "AI-assisted card management, spending insights and suggestions (AppleIntelligenceEnabled)."))
        L.addWidget(_row(TweakID.WalletContactlessPay,
            "Contactless Apple Pay",
            "Enable tap-to-pay NFC transactions (ContactlessPayEnabled)."))
        L.addWidget(_row(TweakID.WalletIDCard,
            "Digital ID Card",
            "Store government-issued ID and driver's licence in Wallet (IDCardEnabled)."))
        L.addWidget(_row(TweakID.WalletTransitCard,
            "Transit Cards",
            "Use Wallet to pay on buses, trains and metro systems (TransitCardEnabled)."))

        # ── Shortcuts iOS 27 ──────────────────────────────────────────────────
        L.addWidget(_hdr("Shortcuts iOS 27 — AI & Natural Language"))
        L.addWidget(_row(TweakID.ShortcutsNLCreation,
            "Natural Language Shortcut Creation",
            "Build automations by describing them in plain English — no blocks required (NaturalLanguageCreationEnabled)."))
        L.addWidget(_row(TweakID.ShortcutsAIOptimize,
            "AI-Optimise Shortcuts",
            "Apple Intelligence suggests improvements to existing shortcuts (AIOptimizeEnabled)."))
        L.addWidget(_row(TweakID.ShortcutsSiriIntegration,
            "Deep Siri Integration",
            "Run any Shortcut by voice through the new iOS 27 Siri app (SiriIntegrationEnabled)."))
        L.addWidget(_row(TweakID.ShortcutsCloudSync,
            "Shortcuts Cloud Sync",
            "Sync all shortcuts across iPhone, iPad and Mac via iCloud (CloudSyncEnabled)."))

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
        load_mros_home_screen()
        load_mros_display()
        load_mros_lock_screen()
        load_mros_keyboard()
        load_mros_notifications()
        load_mros_privacy_apps()
        load_mros_vision_alien()
        load_mros_deep_system()
        load_mros_coremotion()
        load_mros_ai_v2()
        load_mros_siri_ios27()
        load_mros_dynamic_island_ios27()
        load_mros_camera_ai()
        load_mros_satellite()
        load_mros_messages_health()
        for tid in _page_tweak_ids:
            if tid in tweaks:
                tweaks[tid].set_enabled(tid in MAXREGNEROS_MODE_IDS)
        self._sync_checkboxes()
