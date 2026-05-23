from PySide6.QtWidgets import (
    QWidget, QScrollArea, QVBoxLayout, QHBoxLayout,
    QLabel, QCheckBox, QFrame, QSpacerItem, QSizePolicy, QPushButton
)
from PySide6.QtCore import Qt

from ..page import Page
from src.tweaks.tweaks import tweaks, TweakID
from src.tweaks.tweak_loader import (
    load_ios27, load_maxos_ui, load_maxos_apps, load_maxos_system,
    load_maxos_exclusive, _page_tweak_ids, MAXREGNEROS_MODE_IDS
)


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
        brand = QLabel("maxregnerOS")
        brand.setStyleSheet(
            "font-size:26px;font-weight:900;color:#7eb8f7;"
            "letter-spacing:2px;margin-bottom:2px;")
        sub = QLabel("System-wide UI & Feature Overhaul  ·  No BookRestore")
        sub.setStyleSheet("font-size:11px;color:#555;margin-bottom:8px;")
        L.addWidget(brand)
        L.addWidget(sub)

        # ── Action buttons ───────────────────────────────────────────────────
        row = QHBoxLayout()
        b_all  = _btn("⚡ maxregnerOS Mode", "#1a5fb4","#2a6ebb","#0f3a7a")
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
            "Disable Profanity Filter", "Remove Siri's explicit language filter."))
        L.addWidget(_row(TweakID.Siri2CallScreening,
            "Siri on Lock Screen", "Siri from any lock screen state (AssistantAllowedForAnyLockscreen)."))

        # ── Liquid Glass per-app ──────────────────────────────────────────────
        L.addWidget(_hdr("Liquid Glass — Per-App Extensions"))
        L.addWidget(_div())
        for tid, name, flag in [
            (TweakID.SolariumFFMessages,     "Messages",      "Messages.Solarium"),
            (TweakID.SolariumFFMaps,         "Maps",          "Maps.Solarium"),
            (TweakID.SolariumFFSafari,       "Safari",        "MobileSafari.Solarium"),
            (TweakID.SolariumFFSpotlight,    "Spotlight",     "Spotlight.Solarium"),
            (TweakID.SolariumFFControlCenter,"Control Centre","ControlCenter.Solarium"),
            (TweakID.SolariumFFNotifications,"Notifications", "UserNotificationsUI.Solarium"),
            (TweakID.SolariumFFWidgets,      "Widgets",       "WidgetKit.Solarium"),
            (TweakID.SolariumFFMusic,        "Music",         "Music.Solarium"),
            (TweakID.SolariumFFPodcasts,     "Podcasts",      "Podcasts.Solarium"),
            (TweakID.SolariumFFPhone,        "Phone",         "Phone.Solarium"),
            (TweakID.SolariumFFCalendar,     "Calendar",      "Calendar.Solarium"),
            (TweakID.SolariumFFReminders,    "Reminders",     "Reminders.Solarium"),
            (TweakID.SolariumFFNotes,        "Notes",         "Notes.Solarium"),
        ]:
            L.addWidget(_row(tid, f"Liquid Glass in {name}",
                f"Enable Solarium Liquid Glass for {name} ({flag} feature flag)."))

        # ── Liquid Glass fine-tuning ──────────────────────────────────────────
        L.addWidget(_hdr("Liquid Glass — Fine-Tuning"))
        L.addWidget(_div())
        L.addWidget(_row(TweakID.NoLiquidStatusBar,
            "Disable Glass on Status Bar", "Remove glass material from status bar (SBDisableGlassStatusBar)."))
        L.addWidget(_row(TweakID.NoLiquidNotifications,
            "Disable Glass on Notifications", "Solid surfaces instead of glass for banners (SBDisableGlassNotifications)."))
        L.addWidget(_row(TweakID.SolariumHighContrast,
            "High Contrast Glass", "Increase contrast of glass layers (SolariumHighContrast)."))
        L.addWidget(_row(TweakID.SolariumForceLightTint,
            "Force Light Tint", "Always render Liquid Glass with a light tint (SolariumForceLightTint)."))
        L.addWidget(_row(TweakID.SolariumMaxBlur,
            "Maximum Blur Radius", "Max blur radius on all Liquid Glass surfaces (SolariumMaxBlur)."))

        # ── SpringBoard managed prefs ─────────────────────────────────────────
        L.addWidget(_hdr("SpringBoard — Managed Preferences"))
        L.addWidget(_div())
        L.addWidget(_row(TweakID.SBShowBatteryPercentageAlways,
            "Always Show Battery %", "Force battery % in status bar (SBUIForceDisplayBatteryPercentageNew)."))
        L.addWidget(_row(TweakID.SBHideHomeIndicator,
            "Hide Home Bar", "Remove the home indicator at the bottom (SBHideHomeIndicator)."))
        L.addWidget(_row(TweakID.SBDisableParallaxEffect,
            "Disable Parallax", "Disable icon/wallpaper parallax depth effect (SBDisableParallax)."))
        L.addWidget(_row(TweakID.SBAlwaysGlassHeaders,
            "Always Show Glass Headers", "Keep section headers with glass background visible (SBAlwaysShowGlassGroupHeaders)."))
        L.addWidget(_row(TweakID.SBExpandedDynamicIsland,
            "Persistent Expanded Dynamic Island", "Keep Dynamic Island expanded (SBEnableExpandedDynamicIslandPersistent)."))
        L.addWidget(_row(TweakID.SBAlwaysShowClockDI,
            "Clock with Dynamic Island", "Show clock when Dynamic Island is active (SBShowClockWithDynamicIsland)."))

        # ── Audio Processing ──────────────────────────────────────────────────
        L.addWidget(_hdr("Audio Processing"))
        L.addWidget(_div())
        L.addWidget(_row(TweakID.AudioSpatialDefault,
            "Spatial Audio Processing", "CoreAudio spatial audio pipeline (CoreAudio.SpatialAudioProcessing)."))
        L.addWidget(_row(TweakID.AudioEnhancedSpeaker,
            "Enhanced Speaker Output", "AVFoundation enhanced speaker stage (AVFoundation.EnhancedSpeakerOutput)."))
        L.addWidget(_row(TweakID.AudioPersonalizedSpatial,
            "Personalized Spatial Audio", "Personalised spatial rendering (AVFoundation.PersonalizedSpatialAudio)."))
        L.addWidget(_row(TweakID.AudioBackgroundSounds,
            "Background Sounds", "Extended background sounds flag (Accessibility.BackgroundSounds)."))
        L.addWidget(_row(TweakID.AudioHeadphoneAccom,
            "Headphone Accommodations", "Headphone hearing accommodations (Accessibility.HeadphoneAccommodations)."))
        L.addWidget(_row(TweakID.AudioLoudnessNorm,
            "Loudness Normalisation", "Normalise loudness across playback (AVFoundation.LoudnessNormalization)."))
        L.addWidget(_row(TweakID.AudioSoundEffectsEnabled,
            "System Sound Effects", "Force system sound effects on (SBSoundEffectsEnabled)."))
        L.addWidget(_row(TweakID.AudioHapticsSync,
            "Audio-Haptics Sync", "Synchronised audio+haptic patterns (SBAudioHapticsSyncEnabled)."))

        # ── SpringBoard UI feature flags ──────────────────────────────────────
        L.addWidget(_hdr("SpringBoard UI — Feature Flags"))
        L.addWidget(_div())
        for tid, name, flag in [
            (TweakID.SBFFFloatingDock,            "Floating Dock",               "SpringBoard.FloatingDock"),
            (TweakID.SBFFDenseHomeScreen,         "Dense Home Screen Grid",       "SpringBoard.DenseHomeScreen"),
            (TweakID.SBFFAppSwitcherV2,           "Enhanced App Switcher",        "SpringBoard.EnhancedAppSwitcher"),
            (TweakID.SBFFGlassFolders,            "Liquid Glass Folders",         "SpringBoard.LiquidGlassFolders"),
            (TweakID.SBFFLiveActivitiesPersistent,"Persistent Live Activities",   "SpringBoard.PersistentLiveActivities"),
            (TweakID.SBFFAdaptiveGrid,            "Adaptive Home Screen Grid",    "SpringBoard.HomeScreenAdaptiveGrid"),
            (TweakID.SBFFContextWidgets,          "Contextual Widgets",           "SpringBoard.ContextualWidgets"),
            (TweakID.SBFFProximityAnimations,     "Proximity-Based Animations",   "SpringBoard.ProximityBasedAnimations"),
            (TweakID.SBFFLargeWidgetGrid,         "Large Widget Grid Size",       "SpringBoard.LargeWidgetGridSize"),
            (TweakID.SBFFDynamicBackground,       "Dynamic Background Adaptation","SpringBoard.DynamicBackgroundAdaptation"),
            (TweakID.SBFFGlassIconShimmer,        "Glass Icon Shimmer",           "SpringBoard.GlassIconShimmer"),
            (TweakID.SBFFPageIndicatorRedesign,   "Page Indicator Redesign",      "SpringBoard.PageIndicatorRedesign"),
            (TweakID.SBFFEnhancedAppLibrary,      "Enhanced App Library Search",  "SpringBoard.EnhancedAppLibrarySearch"),
            (TweakID.SBFFGlassSectionDividers,    "Glass Section Dividers",       "SpringBoard.GlassSectionDividers"),
            (TweakID.SBFFDebugUIOverlay,          "UI Debug Overlay",             "SpringBoard.UIDebugOverlay"),
        ]:
            L.addWidget(_row(tid, name, f"Feature flag: {flag}"))

        # ── UIKit feature flags ───────────────────────────────────────────────
        L.addWidget(_hdr("UIKit — Feature Flags"))
        L.addWidget(_div())
        for tid, name, flag in [
            (TweakID.UIKitFFGlassSheets,            "Glass Bottom Sheets",         "UIKit.GlassBottomSheets"),
            (TweakID.UIKitFFPillButtons,            "Pill-Shaped Buttons",         "UIKit.PillShapedButtons"),
            (TweakID.UIKitFFLargeNavHeaders,        "Large Navigation Headers",    "UIKit.LargeNavigationHeaders"),
            (TweakID.UIKitFFSwipeBackV2,            "Swipe-Back Gesture V2",       "UIKit.SwipeBackGestureV2"),
            (TweakID.UIKitFFFloatingMenus,          "Floating Menu Presentations", "UIKit.FloatingMenuPresentations"),
            (TweakID.UIKitFFCardLayouts,            "Adaptive Card Layouts",       "UIKit.AdaptiveCardLayouts"),
            (TweakID.UIKitFFRubberBandPhysics,      "Rubber-Band Scroll Physics",  "UIKit.RubberBandScrollPhysics"),
            (TweakID.UIKitFFGlassAlerts,            "Glass Alert Views",           "UIKit.GlassAlertViews"),
            (TweakID.UIKitFFCompactProgress,        "Compact Progress Indicators", "UIKit.CompactProgressIndicators"),
            (TweakID.UIKitFFHapticKeyboard,         "Haptic Keyboard Feedback",    "UIKit.HapticKeyboardFeedback"),
            (TweakID.UIKitFFEnhancedTextRendering,  "Enhanced Text Rendering",     "UIKit.EnhancedTextRendering"),
            (TweakID.UIKitFFDynamicColorAdaptation, "Dynamic Color Adaptation",    "UIKit.DynamicColorAdaptation"),
        ]:
            L.addWidget(_row(tid, name, f"Feature flag: {flag}"))

        # ── Photos & Camera ───────────────────────────────────────────────────
        L.addWidget(_hdr("Photos & Camera — Feature Flags"))
        L.addWidget(_div())
        for tid, name, flag in [
            (TweakID.PhotosFFEnhancedEditing,   "Enhanced Photo Editing",     "Photos.EnhancedEditing"),
            (TweakID.PhotosFFAIAlbums,          "AI Smart Albums",            "Photos.AISmartAlbums"),
            (TweakID.PhotosFFMemoriesV2,        "Memories V2",                "Photos.MemoriesV2"),
            (TweakID.PhotosFFImprovedSearch,    "Improved Photos Search",     "Photos.ImprovedSearch"),
            (TweakID.CameraFFProResVideo,       "ProRes Video",               "Camera.ProResVideoEnabled"),
            (TweakID.CameraFFMacroPro,          "Macro Photography Pro",      "Camera.MacroPro"),
            (TweakID.CameraFFNightModePortrait, "Night Mode Portrait",        "Camera.NightModePortrait"),
            (TweakID.CameraFFProRAWMax,         "ProRAW Max",                 "Camera.ProRAWMax"),
            (TweakID.CameraFFCinematicV2,       "Cinematic Mode V2",          "Camera.CinematicModeV2"),
            (TweakID.CameraFFQuantumHDR,        "Quantum HDR",                "Camera.QuantumHDR"),
        ]:
            L.addWidget(_row(tid, name, f"Feature flag: {flag}"))

        # ── Messages & FaceTime ───────────────────────────────────────────────
        L.addWidget(_hdr("Messages & FaceTime — Feature Flags"))
        L.addWidget(_div())
        for tid, name, flag in [
            (TweakID.MsgFFEnhancedSearch,          "Enhanced Message Search",     "Messages.EnhancedSearch"),
            (TweakID.MsgFFEffectsV2,               "Message Effects V2",          "Messages.EffectsV2"),
            (TweakID.MsgFFCollaborativeSharing,    "Collaborative Sharing",       "Messages.CollaborativeSharing"),
            (TweakID.MsgFFRichLinksV2,             "Rich Link Previews V2",       "Messages.RichLinksV2"),
            (TweakID.FaceTimeFFPersonSegmentation, "Person Segmentation",         "FaceTime.PersonSegmentation"),
            (TweakID.FaceTimeFFReactionAnimations, "Reaction Animations",         "FaceTime.ReactionAnimations"),
            (TweakID.FaceTimeFFSharedPlaybackV2,   "Shared Playback V2",          "FaceTime.SharedPlaybackV2"),
            (TweakID.FaceTimeFFSpatialAudioCall,   "Spatial Audio Calls",         "FaceTime.SpatialAudioCall"),
        ]:
            L.addWidget(_row(tid, name, f"Feature flag: {flag}"))

        # ── Maps ─────────────────────────────────────────────────────────────
        L.addWidget(_hdr("Maps & Location — Feature Flags"))
        L.addWidget(_div())
        for tid, name, flag in [
            (TweakID.MapsFFImmersiveView,      "Immersive View",            "Maps.ImmersiveView"),
            (TweakID.MapsFFARWalkDirections,   "AR Walk Directions",        "Maps.ARWalkDirections"),
            (TweakID.MapsFFOfflineEnhanced,    "Enhanced Offline Maps",     "Maps.OfflineMapsEnhanced"),
            (TweakID.MapsFFRealtimeTrafficV2,  "Realtime Traffic V2",       "Maps.RealtimeTrafficV2"),
            (TweakID.MapsFF3DPlaceCards,       "3D Place Cards",            "Maps.PlaceCards3D"),
            (TweakID.MapsFFElevationData,      "Elevation Data Overlay",    "Maps.ElevationData"),
        ]:
            L.addWidget(_row(tid, name, f"Feature flag: {flag}"))

        # ── Safari ────────────────────────────────────────────────────────────
        L.addWidget(_hdr("Safari & WebKit — Feature Flags"))
        L.addWidget(_div())
        for tid, name, flag in [
            (TweakID.SafariFFEnhancedPrivacy,    "Enhanced Privacy Mode",    "MobileSafari.EnhancedPrivacyMode"),
            (TweakID.SafariFFTabGroupsV2,        "Tab Groups V2",            "MobileSafari.TabGroupsV2"),
            (TweakID.SafariFFWebExtensionsAPI,   "Web Extensions API",       "MobileSafari.WebExtensionsAPI"),
            (TweakID.SafariFFStartPageRedesign,  "Start Page Redesign",      "MobileSafari.StartPageRedesign"),
            (TweakID.SafariFFFloatingAddressBar, "Floating Address Bar",     "MobileSafari.FloatingAddressBar"),
            (TweakID.SafariFFReaderModeV2,       "Reader Mode V2",           "MobileSafari.ReaderModeV2"),
        ]:
            L.addWidget(_row(tid, name, f"Feature flag: {flag}"))

        # ── Widgets & Live Activities ─────────────────────────────────────────
        L.addWidget(_hdr("Widgets & Live Activities — Feature Flags"))
        L.addWidget(_div())
        for tid, name, flag in [
            (TweakID.WidgetFFInteractiveWidgets, "Interactive Widgets",       "WidgetKit.InteractiveWidgets"),
            (TweakID.WidgetFFLargeFormat,        "Large Widget Format",       "WidgetKit.LargeWidgetFormat"),
            (TweakID.WidgetFFAnimatedWidgets,    "Animated Widgets",          "WidgetKit.AnimatedWidgets"),
            (TweakID.LiveActFFPersistentMode,    "Persistent Live Activities","LiveActivities.PersistentMode"),
            (TweakID.LiveActFFGlassPresentation, "Glass Live Activity UI",    "LiveActivities.GlassPresentation"),
            (TweakID.LiveActFFStandbyV2,         "Standby Mode V2",           "LiveActivities.StandbyModeV2"),
        ]:
            L.addWidget(_row(tid, name, f"Feature flag: {flag}"))

        # ── Lock Screen & Notifications ───────────────────────────────────────
        L.addWidget(_hdr("Lock Screen & Notifications — Feature Flags"))
        L.addWidget(_div())
        for tid, name, flag in [
            (TweakID.LockFFWidgetsV2,           "Lock Screen Widgets V2",    "SpringBoard.LockScreenWidgetsV2"),
            (TweakID.LockFFDepthEffectClock,    "Depth-Effect Clock",        "SpringBoard.DepthEffectClock"),
            (TweakID.LockFFLiveWeatherBG,       "Live Weather Background",   "SpringBoard.LiveWeatherBackground"),
            (TweakID.LockFFAlwaysOnDisplayV2,   "Always-On Display V2",      "SpringBoard.AlwaysOnDisplayV2"),
            (TweakID.NotifFFStackedBanners,     "Stacked Notification Banners","UserNotificationsUI.StackedBanners"),
            (TweakID.NotifFFGlassNotifications, "Glass Notification Banners","UserNotificationsUI.GlassNotifications"),
            (TweakID.NotifFFQuickRepliesV2,     "Quick Replies V2",          "UserNotificationsUI.QuickRepliesV2"),
            (TweakID.NotifFFSummaryV2,          "Notification Summary V2",   "UserNotificationsUI.NotificationSummaryV2"),
        ]:
            L.addWidget(_row(tid, name, f"Feature flag: {flag}"))

        # ── System Performance ────────────────────────────────────────────────
        L.addWidget(_hdr("System Performance — Feature Flags"))
        L.addWidget(_div())
        for tid, name, flag in [
            (TweakID.PerfFFEnhancedLowPower,     "Enhanced Low Power Mode",  "SpringBoard.EnhancedLowPowerMode"),
            (TweakID.PerfFFBackgroundRefreshV2,  "Background Refresh V2",    "SpringBoard.BackgroundRefreshV2"),
            (TweakID.PerfFFLowLatencyAudio,      "Low-Latency Audio",        "CoreAudio.LowLatencyProcessing"),
            (TweakID.PerfFFHardwareAcceleration, "Hardware Acceleration",    "AVFoundation.HardwareAcceleration"),
            (TweakID.PerfFFThermalStatusUI,      "Thermal Status UI",        "SpringBoard.ThermalStatusUI"),
            (TweakID.PerfFFMemoryPressureMonitor,"Memory Pressure Monitor",  "SpringBoard.MemoryPressureMonitor"),
            (TweakID.PerfFFProcessPriorityBoost, "Process Priority Boost",   "SpringBoard.ProcessPriorityBoost"),
            (TweakID.PerfFFUltraLowLatencyInput, "Ultra-Low-Latency Input",  "SpringBoard.UltraLowLatencyInput"),
        ]:
            L.addWidget(_row(tid, name, f"Feature flag: {flag}"))

        # ── maxregnerOS Exclusive ─────────────────────────────────────────────
        L.addWidget(_hdr("✦ maxregnerOS Exclusive"))
        L.addWidget(_div())
        for tid, name, flag in [
            (TweakID.MaxOSGlassEverywhere,      "Glass Everywhere",          "SpringBoard.GlassEverywhere"),
            (TweakID.MaxOSFluidMotionEngine,    "Fluid Motion Engine",       "UIKit.FluidMotionEngine"),
            (TweakID.MaxOSNeuralEngineBoost,    "Neural Engine Boost",       "CoreML.EnhancedNeuralEngine"),
            (TweakID.MaxOSProDisplayRendering,  "Pro Display Rendering",     "CoreGraphics.ProDisplayRendering"),
            (TweakID.MaxOSHyperSmoothScrolling, "HyperSmooth Scrolling",     "UIKit.HyperSmoothScrolling"),
            (TweakID.MaxOSChromaticAberration,  "Chromatic Aberration FX",   "CoreImage.ChromaticAberrationEffect"),
            (TweakID.MaxOSDepthSensingV2,       "Depth Sensing V2",          "ARKit.DepthSensingV2"),
            (TweakID.MaxOSAmbientIntelligence,  "Ambient Intelligence",      "Siri.AmbientIntelligence"),
            (TweakID.MaxOSProHapticsEngine,     "Pro Haptics Engine",        "CoreHaptics.ProHapticsEngine"),
            (TweakID.MaxOSDynamicIslandPro,     "Dynamic Island Pro",        "SpringBoard.DynamicIslandPro"),
        ]:
            L.addWidget(_row(tid, name, f"Feature flag: {flag}"))

    # ── callbacks ────────────────────────────────────────────────────────────

    def _enable_all(self):
        for tid in _page_tweak_ids:
            if tid in tweaks:
                tweaks[tid].set_enabled(True)

    def _disable_all(self):
        for tid in _page_tweak_ids:
            if tid in tweaks:
                tweaks[tid].set_enabled(False)

    def _maxregneros_mode(self):
        """Enable the curated maxregnerOS signature set and disable the rest."""
        for tid in _page_tweak_ids:
            if tid in tweaks:
                tweaks[tid].set_enabled(tid in MAXREGNEROS_MODE_IDS)

    def load_page(self):
        load_ios27()
        load_maxos_ui()
        load_maxos_apps()
        load_maxos_system()
        load_maxos_exclusive()
