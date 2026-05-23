from PySide6.QtWidgets import (
    QWidget, QScrollArea, QVBoxLayout, QHBoxLayout,
    QLabel, QCheckBox, QFrame, QSpacerItem, QSizePolicy, QPushButton
)
from PySide6.QtCore import Qt

from ..page import Page
from src.tweaks.tweaks import tweaks, TweakID
from src.tweaks.tweak_loader import (
    load_ios27, load_maxos_ui, load_maxos_apps, load_maxos_system,
    load_maxos_exclusive, load_maxos_haptics_ar, load_maxos_connectivity,
    load_maxos_cloud_health, load_maxos_wallet_home_focus,
    load_maxos_privacy_shortcuts_org, load_maxos_reminders_files,
    load_maxos_gaming_media, load_maxos_extended_apps, load_maxos_system_core,
    load_mros_kernel, load_mros_exclusive_v2,
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

        # ── Audio Processing ──────────────────────────────────────────────────
        L.addWidget(_hdr("Audio Processing"))
        L.addWidget(_div())
        for tid, name, flag in [
            (TweakID.AudioSpatialDefault,      "Spatial Audio Processing",   "CoreAudio.SpatialAudioProcessing"),
            (TweakID.AudioEnhancedSpeaker,     "Enhanced Speaker Output",    "AVFoundation.EnhancedSpeakerOutput"),
            (TweakID.AudioPersonalizedSpatial, "Personalized Spatial Audio", "AVFoundation.PersonalizedSpatialAudio"),
            (TweakID.AudioBackgroundSounds,    "Background Sounds",          "Accessibility.BackgroundSounds"),
            (TweakID.AudioHeadphoneAccom,      "Headphone Accommodations",   "Accessibility.HeadphoneAccommodations"),
            (TweakID.AudioLoudnessNorm,        "Loudness Normalisation",     "AVFoundation.LoudnessNormalization"),
        ]:
            L.addWidget(_row(tid, name, f"Feature flag: {flag}"))
        L.addWidget(_row(TweakID.AudioSoundEffectsEnabled,
            "System Sound Effects", "Force system sound effects on (SBSoundEffectsEnabled)."))
        L.addWidget(_row(TweakID.AudioHapticsSync,
            "Audio-Haptics Sync", "Synchronised audio+haptic patterns (SBAudioHapticsSyncEnabled)."))

        # ── SpringBoard UI feature flags ──────────────────────────────────────
        L.addWidget(_hdr("SpringBoard UI — Feature Flags"))
        L.addWidget(_div())
        for tid, name, flag in [
            (TweakID.SBFFFloatingDock,            "Floating Dock",               "SpringBoard.FloatingDock"),
            (TweakID.SBFFDenseHomeScreen,         "Dense Home Screen Grid",      "SpringBoard.DenseHomeScreen"),
            (TweakID.SBFFAppSwitcherV2,           "Enhanced App Switcher",       "SpringBoard.EnhancedAppSwitcher"),
            (TweakID.SBFFGlassFolders,            "Liquid Glass Folders",        "SpringBoard.LiquidGlassFolders"),
            (TweakID.SBFFLiveActivitiesPersistent,"Persistent Live Activities",  "SpringBoard.PersistentLiveActivities"),
            (TweakID.SBFFAdaptiveGrid,            "Adaptive Home Screen Grid",   "SpringBoard.HomeScreenAdaptiveGrid"),
            (TweakID.SBFFContextWidgets,          "Contextual Widgets",          "SpringBoard.ContextualWidgets"),
            (TweakID.SBFFProximityAnimations,     "Proximity-Based Animations",  "SpringBoard.ProximityBasedAnimations"),
            (TweakID.SBFFLargeWidgetGrid,         "Large Widget Grid Size",      "SpringBoard.LargeWidgetGridSize"),
            (TweakID.SBFFDynamicBackground,       "Dynamic Background Adapt.",   "SpringBoard.DynamicBackgroundAdaptation"),
            (TweakID.SBFFGlassIconShimmer,        "Glass Icon Shimmer",          "SpringBoard.GlassIconShimmer"),
            (TweakID.SBFFPageIndicatorRedesign,   "Page Indicator Redesign",     "SpringBoard.PageIndicatorRedesign"),
            (TweakID.SBFFEnhancedAppLibrary,      "Enhanced App Library Search", "SpringBoard.EnhancedAppLibrarySearch"),
            (TweakID.SBFFGlassSectionDividers,    "Glass Section Dividers",      "SpringBoard.GlassSectionDividers"),
            (TweakID.SBFFDebugUIOverlay,          "UI Debug Overlay",            "SpringBoard.UIDebugOverlay"),
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
            (TweakID.PhotosFFEnhancedEditing,   "Enhanced Photo Editing",    "Photos.EnhancedEditing"),
            (TweakID.PhotosFFAIAlbums,          "AI Smart Albums",           "Photos.AISmartAlbums"),
            (TweakID.PhotosFFMemoriesV2,        "Memories V2",               "Photos.MemoriesV2"),
            (TweakID.PhotosFFImprovedSearch,    "Improved Photos Search",    "Photos.ImprovedSearch"),
            (TweakID.CameraFFProResVideo,       "ProRes Video",              "Camera.ProResVideoEnabled"),
            (TweakID.CameraFFMacroPro,          "Macro Photography Pro",     "Camera.MacroPro"),
            (TweakID.CameraFFNightModePortrait, "Night Mode Portrait",       "Camera.NightModePortrait"),
            (TweakID.CameraFFProRAWMax,         "ProRAW Max",                "Camera.ProRAWMax"),
            (TweakID.CameraFFCinematicV2,       "Cinematic Mode V2",         "Camera.CinematicModeV2"),
            (TweakID.CameraFFQuantumHDR,        "Quantum HDR",               "Camera.QuantumHDR"),
        ]:
            L.addWidget(_row(tid, name, f"Feature flag: {flag}"))

        # ── Messages & FaceTime ───────────────────────────────────────────────
        L.addWidget(_hdr("Messages & FaceTime — Feature Flags"))
        L.addWidget(_div())
        for tid, name, flag in [
            (TweakID.MsgFFEnhancedSearch,          "Enhanced Message Search",  "Messages.EnhancedSearch"),
            (TweakID.MsgFFEffectsV2,               "Message Effects V2",       "Messages.EffectsV2"),
            (TweakID.MsgFFCollaborativeSharing,    "Collaborative Sharing",    "Messages.CollaborativeSharing"),
            (TweakID.MsgFFRichLinksV2,             "Rich Link Previews V2",    "Messages.RichLinksV2"),
            (TweakID.FaceTimeFFPersonSegmentation, "Person Segmentation",      "FaceTime.PersonSegmentation"),
            (TweakID.FaceTimeFFReactionAnimations, "Reaction Animations",      "FaceTime.ReactionAnimations"),
            (TweakID.FaceTimeFFSharedPlaybackV2,   "Shared Playback V2",       "FaceTime.SharedPlaybackV2"),
            (TweakID.FaceTimeFFSpatialAudioCall,   "Spatial Audio Calls",      "FaceTime.SpatialAudioCall"),
        ]:
            L.addWidget(_row(tid, name, f"Feature flag: {flag}"))

        # ── Maps & Safari ─────────────────────────────────────────────────────
        L.addWidget(_hdr("Maps & Safari — Feature Flags"))
        L.addWidget(_div())
        for tid, name, flag in [
            (TweakID.MapsFFImmersiveView,      "Immersive View",            "Maps.ImmersiveView"),
            (TweakID.MapsFFARWalkDirections,   "AR Walk Directions",        "Maps.ARWalkDirections"),
            (TweakID.MapsFFOfflineEnhanced,    "Enhanced Offline Maps",     "Maps.OfflineMapsEnhanced"),
            (TweakID.MapsFFRealtimeTrafficV2,  "Realtime Traffic V2",       "Maps.RealtimeTrafficV2"),
            (TweakID.MapsFF3DPlaceCards,       "3D Place Cards",            "Maps.PlaceCards3D"),
            (TweakID.MapsFFElevationData,      "Elevation Data Overlay",    "Maps.ElevationData"),
            (TweakID.SafariFFEnhancedPrivacy,  "Enhanced Privacy Mode",     "MobileSafari.EnhancedPrivacyMode"),
            (TweakID.SafariFFTabGroupsV2,      "Tab Groups V2",             "MobileSafari.TabGroupsV2"),
            (TweakID.SafariFFWebExtensionsAPI, "Web Extensions API",        "MobileSafari.WebExtensionsAPI"),
            (TweakID.SafariFFStartPageRedesign,"Start Page Redesign",       "MobileSafari.StartPageRedesign"),
            (TweakID.SafariFFFloatingAddressBar,"Floating Address Bar",     "MobileSafari.FloatingAddressBar"),
            (TweakID.SafariFFReaderModeV2,     "Reader Mode V2",            "MobileSafari.ReaderModeV2"),
        ]:
            L.addWidget(_row(tid, name, f"Feature flag: {flag}"))

        # ── Widgets, Live Activities, Lock Screen & Notifications ─────────────
        L.addWidget(_hdr("Widgets, Live Activities & Notifications"))
        L.addWidget(_div())
        for tid, name, flag in [
            (TweakID.WidgetFFInteractiveWidgets, "Interactive Widgets",        "WidgetKit.InteractiveWidgets"),
            (TweakID.WidgetFFLargeFormat,        "Large Widget Format",        "WidgetKit.LargeWidgetFormat"),
            (TweakID.WidgetFFAnimatedWidgets,    "Animated Widgets",           "WidgetKit.AnimatedWidgets"),
            (TweakID.LiveActFFPersistentMode,    "Persistent Live Activities", "LiveActivities.PersistentMode"),
            (TweakID.LiveActFFGlassPresentation, "Glass Live Activity UI",     "LiveActivities.GlassPresentation"),
            (TweakID.LiveActFFStandbyV2,         "Standby Mode V2",            "LiveActivities.StandbyModeV2"),
            (TweakID.LockFFWidgetsV2,            "Lock Screen Widgets V2",     "SpringBoard.LockScreenWidgetsV2"),
            (TweakID.LockFFDepthEffectClock,     "Depth-Effect Clock",         "SpringBoard.DepthEffectClock"),
            (TweakID.LockFFLiveWeatherBG,        "Live Weather Background",    "SpringBoard.LiveWeatherBackground"),
            (TweakID.LockFFAlwaysOnDisplayV2,    "Always-On Display V2",       "SpringBoard.AlwaysOnDisplayV2"),
            (TweakID.NotifFFStackedBanners,      "Stacked Notification Banners","UserNotificationsUI.StackedBanners"),
            (TweakID.NotifFFGlassNotifications,  "Glass Notification Banners", "UserNotificationsUI.GlassNotifications"),
            (TweakID.NotifFFQuickRepliesV2,      "Quick Replies V2",           "UserNotificationsUI.QuickRepliesV2"),
            (TweakID.NotifFFSummaryV2,           "Notification Summary V2",    "UserNotificationsUI.NotificationSummaryV2"),
        ]:
            L.addWidget(_row(tid, name, f"Feature flag: {flag}"))

        # ── System Performance ────────────────────────────────────────────────
        L.addWidget(_hdr("System Performance — Feature Flags"))
        L.addWidget(_div())
        for tid, name, flag in [
            (TweakID.PerfFFEnhancedLowPower,     "Enhanced Low Power Mode",   "SpringBoard.EnhancedLowPowerMode"),
            (TweakID.PerfFFBackgroundRefreshV2,  "Background Refresh V2",     "SpringBoard.BackgroundRefreshV2"),
            (TweakID.PerfFFLowLatencyAudio,      "Low-Latency Audio",         "CoreAudio.LowLatencyProcessing"),
            (TweakID.PerfFFHardwareAcceleration, "Hardware Acceleration",     "AVFoundation.HardwareAcceleration"),
            (TweakID.PerfFFThermalStatusUI,      "Thermal Status UI",         "SpringBoard.ThermalStatusUI"),
            (TweakID.PerfFFMemoryPressureMonitor,"Memory Pressure Monitor",   "SpringBoard.MemoryPressureMonitor"),
            (TweakID.PerfFFProcessPriorityBoost, "Process Priority Boost",    "SpringBoard.ProcessPriorityBoost"),
            (TweakID.PerfFFUltraLowLatencyInput, "Ultra-Low-Latency Input",   "SpringBoard.UltraLowLatencyInput"),
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

        # ── Haptics, ARKit & Machine Learning ─────────────────────────────────
        L.addWidget(_hdr("Haptics, ARKit & Machine Learning"))
        L.addWidget(_div())
        for tid, name, flag in [
            (TweakID.HapticsPatternPlayback,     "Haptic Pattern Playback",      "CoreHaptics.PatternPlayback"),
            (TweakID.HapticsAdvancedComposition, "Advanced Haptic Composition",  "CoreHaptics.AdvancedComposition"),
            (TweakID.HapticsSyncedPlayback,      "Synced Audio+Haptic Playback", "CoreHaptics.SyncedPlayback"),
            (TweakID.HapticsAdaptiveTriggers,    "Adaptive Haptic Triggers",     "CoreHaptics.AdaptiveTriggers"),
            (TweakID.HapticsProEffectsEngine,    "Pro Haptics Effects Engine",   "CoreHaptics.ProEffectsEngine"),
            (TweakID.ARKitWorldTrackingV3,       "AR World Tracking V3",         "ARKit.WorldTrackingV3"),
            (TweakID.ARKitFaceTrackingPro,       "AR Face Tracking Pro",         "ARKit.FaceTrackingPro"),
            (TweakID.ARKitObjectScanningPro,     "AR Object Scanning Pro",       "ARKit.ObjectScanningPro"),
            (TweakID.ARKitGeospatialV2,          "AR Geospatial Anchors V2",     "ARKit.GeospatialV2"),
            (TweakID.ARKitOcclusionV2,           "AR Occlusion V2",              "ARKit.OcclusionV2"),
            (TweakID.VisionLiveTextV3,           "Live Text V3",                 "Vision.LiveTextV3"),
            (TweakID.VisionDocumentScannerPro,   "Document Scanner Pro",         "Vision.DocumentScannerPro"),
            (TweakID.VisionSubjectLiftV2,        "Subject Lift V2",              "Vision.SubjectLiftV2"),
            (TweakID.VisionStyleTransferV2,      "Style Transfer V2",            "Vision.StyleTransferV2"),
            (TweakID.VisionPersonSegV2,          "Person Segmentation V2",       "Vision.PersonSegmentationV2"),
            (TweakID.CoreMLOnDeviceV2,           "On-Device Inference V2",       "CoreML.OnDeviceInferenceV2"),
            (TweakID.CoreMLNeuralMaxUtil,        "Neural Engine Max Utilization","CoreML.NeuralEngineMaxUtilization"),
            (TweakID.CoreMLAdaptiveInference,    "Adaptive ML Inference",        "CoreML.AdaptiveInference"),
            (TweakID.CoreMLPrivateCompute,       "Private Cloud Compute",        "CoreML.PrivateCloudCompute"),
            (TweakID.CoreMLStreamingInference,   "Streaming ML Inference",       "CoreML.StreamingInference"),
        ]:
            L.addWidget(_row(tid, name, f"Feature flag: {flag}"))

        # ── Connectivity ──────────────────────────────────────────────────────
        L.addWidget(_hdr("Connectivity — Network, Bluetooth & Location"))
        L.addWidget(_div())
        for tid, name, flag in [
            (TweakID.NetHTTP3Default,           "HTTP/3 Default",              "Network.HTTP3Default"),
            (TweakID.NetQUICEnabled,            "QUIC Protocol",               "Network.QUICEnabled"),
            (TweakID.NetAdaptiveQoS,            "Adaptive QoS",                "Network.AdaptiveQoS"),
            (TweakID.NetPrivacyProxyV2,         "Privacy Proxy V2",            "Network.PrivacyProxyV2"),
            (TweakID.NetLowDataModeV2,          "Low Data Mode V2",            "Network.LowDataModeV2"),
            (TweakID.BLEEnhancedScanning,       "BLE Enhanced Scanning",       "Bluetooth.EnhancedScanning"),
            (TweakID.BLELeAudioCodecs,          "LE Audio Codecs",             "Bluetooth.LEAudioCodecs"),
            (TweakID.BTCompanionMode,           "Companion Mode",              "Bluetooth.CompanionMode"),
            (TweakID.BTPersonalHotspotV2,       "Personal Hotspot V2",         "Bluetooth.PersonalHotspotV2"),
            (TweakID.LocPrecisionV2,            "Precise Location V2",         "CoreLocation.PreciseLocationV2"),
            (TweakID.LocOfflineGeocoding,       "Offline Geocoding",           "CoreLocation.OfflineGeocoding"),
            (TweakID.LocBackgroundOptimization, "Location Background Opt.",    "CoreLocation.BackgroundOptimization"),
        ]:
            L.addWidget(_row(tid, name, f"Feature flag: {flag}"))

        # ── Cloud Services & Health ───────────────────────────────────────────
        L.addWidget(_hdr("Cloud Services & Health"))
        L.addWidget(_div())
        for tid, name, flag in [
            (TweakID.CloudKitEncryptionV2,      "CloudKit Encryption V2",      "CloudKit.EncryptionV2"),
            (TweakID.CloudKitSyncPriorityV2,    "CloudKit Sync Priority V2",   "CloudKit.SyncPriorityV2"),
            (TweakID.iCloudDriveV2,             "iCloud Drive V2",             "iCloud.DriveV2"),
            (TweakID.iCloudKeyValueV2,          "iCloud Key-Value Store V2",   "iCloud.KeyValueStoreV2"),
            (TweakID.HealthMentalHealthV2,      "Mental Health V2",            "HealthKit.MentalHealthV2"),
            (TweakID.HealthSleepV3,             "Sleep Tracking V3",           "HealthKit.SleepV3"),
            (TweakID.HealthInsightsV2,          "Health Insights V2",          "HealthKit.InsightsV2"),
            (TweakID.HealthCyclingV2,           "Cycling Metrics V2",          "HealthKit.CyclingV2"),
            (TweakID.HealthVisionV2,            "Vision Health V2",            "HealthKit.VisionHealthV2"),
            (TweakID.HealthWorkoutV3,           "Workout V3",                  "HealthKit.WorkoutV3"),
        ]:
            L.addWidget(_row(tid, name, f"Feature flag: {flag}"))

        # ── Wallet, HomeKit & Focus ───────────────────────────────────────────
        L.addWidget(_hdr("Wallet, HomeKit & Focus"))
        L.addWidget(_div())
        for tid, name, flag in [
            (TweakID.WalletCompanionPasses,     "Companion Passes",            "Wallet.CompanionPasses"),
            (TweakID.WalletApplePayV3,          "Apple Pay V3",                "Wallet.ApplePayV3"),
            (TweakID.WalletOrdersV2,            "Order Tracking V2",           "Wallet.OrdersV2"),
            (TweakID.WalletIDVerification,      "ID Verification",             "Wallet.IDVerification"),
            (TweakID.HomeKitMatterV2,           "Matter Protocol V2",          "HomeKit.MatterV2"),
            (TweakID.HomeKitAutomationV3,       "Home Automation V3",          "HomeKit.AutomationV3"),
            (TweakID.HomeKitEnergyV2,           "Energy Management V2",        "HomeKit.EnergyManagementV2"),
            (TweakID.HomeKitCameraV2,           "Camera Streaming V2",         "HomeKit.CameraStreamingV2"),
            (TweakID.FocusContextV2,            "Context Awareness V2",        "Focus.ContextAwarenessV2"),
            (TweakID.FocusFiltersV2Extended,    "Focus Filters V2 Extended",   "Focus.FiltersV2Extended"),
            (TweakID.FocusInsightsV2,           "Focus Insights V2",           "Focus.InsightsV2"),
            (TweakID.ScreenTimeV3,              "Screen Time V3",              "ScreenTime.ScreenTimeV3"),
            (TweakID.ScreenTimeCommunicationV2, "Communication Limits V2",     "ScreenTime.CommunicationLimitsV2"),
        ]:
            L.addWidget(_row(tid, name, f"Feature flag: {flag}"))

        # ── Privacy, Shortcuts & Organization ────────────────────────────────
        L.addWidget(_hdr("Privacy, Shortcuts & Organization"))
        L.addWidget(_div())
        for tid, name, flag in [
            (TweakID.PrivacyAppReportV2,        "App Privacy Report V2",       "Privacy.AppReportV2"),
            (TweakID.PrivacyLocationV2,         "Location Services V2",        "Privacy.LocationServicesV2"),
            (TweakID.PrivacyTrackingV2,         "Tracking Transparency V2",    "Privacy.TrackingTransparencyV2"),
            (TweakID.PrivacySensorV2,           "Sensor Access V2",            "Privacy.SensorAccessV2"),
            (TweakID.PrivacyDataBrokerV2,       "Data Broker Protection V2",   "Privacy.DataBrokerProtectionV2"),
            (TweakID.ShortcutsV3,               "Shortcuts V3",                "Shortcuts.ShortcutsV3"),
            (TweakID.ShortcutsAutomationsV2,    "Automations V2",              "Shortcuts.AutomationsV2"),
            (TweakID.ShortcutsAIActions,        "AI Actions",                  "Shortcuts.AIActions"),
            (TweakID.ShortcutsAppIntentsV2,     "App Intents V2",              "Shortcuts.AppIntentsV2"),
            (TweakID.CalSuggestionsV2,          "Calendar Suggestions V2",     "Calendar.SuggestionsV2"),
            (TweakID.CalSmartScheduling,        "Smart Scheduling",            "Calendar.SmartScheduling"),
            (TweakID.CalInsightsV2,             "Calendar Insights V2",        "Calendar.InsightsV2"),
            (TweakID.CalSharedCalendarV2,       "Shared Calendar V2",          "Calendar.SharedCalendarV2"),
            (TweakID.ContactsSuggestionsV2,     "Contact Suggestions V2",      "Contacts.SuggestionsV2"),
            (TweakID.ContactsUnifiedViewV2,     "Unified Contacts View V2",    "Contacts.UnifiedViewV2"),
            (TweakID.ContactsSmartGroupV2,      "Smart Contact Groups V2",     "Contacts.SmartGroupV2"),
        ]:
            L.addWidget(_row(tid, name, f"Feature flag: {flag}"))

        # ── Reminders, Notes & Files ──────────────────────────────────────────
        L.addWidget(_hdr("Reminders, Notes & Files"))
        L.addWidget(_div())
        for tid, name, flag in [
            (TweakID.RemindersSuggestionsV2,    "Reminder Suggestions V2",     "Reminders.SuggestionsV2"),
            (TweakID.RemindersCollaborationV2,  "Reminder Collaboration V2",   "Reminders.CollaborationV2"),
            (TweakID.RemindersSmartListsV2,     "Smart Lists V2",              "Reminders.SmartListsV2"),
            (TweakID.NotesCollaborationV2,      "Notes Collaboration V2",      "Notes.CollaborationV2"),
            (TweakID.NotesSearchV2,             "Notes Search V2",             "Notes.SearchV2"),
            (TweakID.NotesTemplatesV2,          "Notes Templates V2",          "Notes.TemplatesV2"),
            (TweakID.FilesTaggingV2,            "Files Tagging V2",            "Files.TaggingV2"),
            (TweakID.FilesSharingV2,            "Files Sharing V2",            "Files.SharingV2"),
            (TweakID.FilesQuickLookV2,          "Files Quick Look V2",         "Files.QuickLookV2"),
        ]:
            L.addWidget(_row(tid, name, f"Feature flag: {flag}"))

        # ── Gaming, Metal & Media ─────────────────────────────────────────────
        L.addWidget(_hdr("Gaming, Metal & Media"))
        L.addWidget(_div())
        for tid, name, flag in [
            (TweakID.GameCenterV3,              "Game Center V3",              "GameKit.GameCenterV3"),
            (TweakID.GameMultiplayerV2,         "Multiplayer V2",              "GameKit.MultiplayerV2"),
            (TweakID.MetalRayTracingV2,         "Metal Ray Tracing V2",        "Metal.RayTracingV2"),
            (TweakID.MetalMLAcceleration,       "Metal ML Acceleration",       "Metal.MLAcceleration"),
            (TweakID.RealityKitV3,              "RealityKit V3",               "RealityKit.RealityKitV3"),
            (TweakID.SpatialComputingV2,        "Spatial Computing V2",        "RealityKit.SpatialComputingV2"),
            (TweakID.MediaTVFloatingPlayer,     "TV Floating Player",          "TVUIKit.FloatingPlayer"),
            (TweakID.MediaMusicLosslessDefault, "Music Lossless Default",      "Music.LosslessDefault"),
            (TweakID.MediaMusicSpatialDefault,  "Music Spatial Default",       "Music.SpatialDefault"),
            (TweakID.MediaPodcastsTranscriptV2, "Podcasts Transcript V2",      "Podcasts.TranscriptV2"),
            (TweakID.MediaFitnessGroupWorkoutV2,"Fitness Group Workout V2",    "Fitness.GroupWorkoutV2"),
        ]:
            L.addWidget(_row(tid, name, f"Feature flag: {flag}"))

        # ── Extended App Capabilities ─────────────────────────────────────────
        L.addWidget(_hdr("Extended App Capabilities"))
        L.addWidget(_div())
        for tid, name, flag in [
            (TweakID.MapsImmersiveViewV2,       "Immersive View V2",           "Maps.ImmersiveViewV2"),
            (TweakID.MapsLookAroundV2,          "Look Around V2",              "Maps.LookAroundV2"),
            (TweakID.MapsFlyoverV2,             "Flyover V2",                  "Maps.FlyoverV2"),
            (TweakID.MapsTransitV2,             "Transit V2",                  "Maps.TransitV2"),
            (TweakID.MapsGuidesV2,              "Guides V2",                   "Maps.GuidesV2"),
            (TweakID.SafariWebCodecAV1,         "Safari AV1 Codec",            "MobileSafari.AV1Codec"),
            (TweakID.SafariPasskeysFull,        "Passkeys Full Support",       "MobileSafari.PasskeysFullSupport"),
            (TweakID.SafariAdBlockingV2,        "Ad Blocking V2",              "MobileSafari.AdBlockingV2"),
            (TweakID.SafariTranslationV2,       "Page Translation V2",         "MobileSafari.TranslationV2"),
            (TweakID.SafariWebExtensionsV2,     "Web Extensions V2",           "MobileSafari.WebExtensionsV2"),
            (TweakID.MsgReactionsV2,            "Message Reactions V2",        "Messages.ReactionsV2"),
            (TweakID.MsgStickerPacksV2,         "Sticker Packs V2",            "Messages.StickerPacksV2"),
            (TweakID.MsgSharePlayV2,            "SharePlay V2",                "Messages.SharePlayV2"),
            (TweakID.MsgGroupFocusSync,         "Group Focus Sync",            "Messages.GroupFocusSync"),
            (TweakID.MsgCheckInV2,              "Check In V2",                 "Messages.CheckInV2"),
            (TweakID.FTHandoffCallsV2,          "FaceTime Handoff V2",         "FaceTime.HandoffCallsV2"),
            (TweakID.FTVideoMessageV2,          "Video Message V2",            "FaceTime.VideoMessageV2"),
            (TweakID.FTSpatialFaceTime,         "Spatial FaceTime",            "FaceTime.SpatialFaceTime"),
            (TweakID.FTGroupCallsV2,            "Group Calls V2",              "FaceTime.GroupCallsV2"),
            (TweakID.FTPortraitModeCall,        "Portrait Mode Call",          "FaceTime.PortraitModeCall"),
            (TweakID.PhotosSharedLibraryV2,     "Shared Library V2",           "Photos.SharedLibraryV2"),
            (TweakID.PhotosCleanUpV2,           "Photos Clean Up V2",          "Photos.CleanUpV2"),
            (TweakID.PhotosMemoryMovieV2,       "Memory Movie V2",             "Photos.MemoryMovieV2"),
            (TweakID.PhotosHDRMax,              "Photos HDR Max",              "Photos.HDRMax"),
            (TweakID.PhotosPortraitLightsV2,    "Portrait Lights V2",          "Photos.PortraitLightsV2"),
            (TweakID.CameraStudioLightV2,       "Studio Light V2",             "Camera.StudioLightV2"),
            (TweakID.CameraActionModeV2,        "Action Mode V2",              "Camera.ActionModeV2"),
            (TweakID.CameraPhotonicEngineV2,    "Photonic Engine V2",          "Camera.PhotonicEngineV2"),
            (TweakID.CameraVideoV3,             "Video V3",                    "Camera.VideoV3"),
            (TweakID.CameraFrontVideoV2,        "Front Camera Video V2",       "Camera.FrontVideoV2"),
        ]:
            L.addWidget(_row(tid, name, f"Feature flag: {flag}"))

        # ── System Core Overrides ─────────────────────────────────────────────
        L.addWidget(_hdr("✦ System Core Overrides"))
        L.addWidget(_div())
        L.addWidget(_row(TweakID.SysCoreProMotion,
            "ProMotion 120Hz Display",
            "Force ProMotion on all content (SBProMotionEnabled)."))
        L.addWidget(_row(TweakID.SysCoreAnimSpeed,
            "Faster Animations",
            "Lower drag coefficient to 0.35 for snappier transitions (UIAnimationDragCoefficient)."))
        L.addWidget(_row(TweakID.SysCoreScrollVelocity,
            "Scroll Velocity Boost",
            "Increased scroll momentum for faster navigation (UIKit.ScrollVelocityBoost)."))
        L.addWidget(_row(TweakID.SysCoreMTLOverlay,
            "Metal Performance Overlay",
            "Real-time GPU/FPS overlay on screen (MTOverlayEnabled)."))
        L.addWidget(_row(TweakID.SysCoreHideCarrier,
            "Hide Carrier Text",
            "Remove carrier name from status bar (SBHideCarrierText)."))
        L.addWidget(_row(TweakID.SysCoreDevSettings,
            "Show Developer Settings",
            "Expose developer settings in system preferences (SBShowDeveloperSettings)."))
        L.addWidget(_row(TweakID.SysCoreAlwaysAOD,
            "Always-On Display Override",
            "Force Always-On Display active (SBAlwaysOnDisplayEnabled)."))
        L.addWidget(_row(TweakID.SysCoreNightShiftMax,
            "Night Shift Max Brightness",
            "Full brightness during Night Shift (CoreDisplay.NightShiftMaxBrightness)."))
        L.addWidget(_row(TweakID.SysCoreAutoRotate,
            "Force Auto-Rotate",
            "Ensure auto-rotation is never disabled (SBDisableAutoRotation=false)."))
        L.addWidget(_row(TweakID.SysCoreHDRVideo,
            "HDR Video Default",
            "Default all video playback to HDR (AVFoundation.HDRVideoDefault)."))

        # ── mROS Kernel Layer ─────────────────────────────────────────────────
        L.addWidget(_hdr("⚙ mROS Kernel Layer — XNU / IOKit / Darwin"))
        L.addWidget(_div())
        for tid, name, flag in [
            (TweakID.KernelThreadPriorityBoost, "Thread Priority Boost",        "XNU.ThreadPriorityBoost"),
            (TweakID.KernelMemoryCompression,   "Memory Compression V2",        "XNU.MemoryCompressionV2"),
            (TweakID.KernelIOSchedulerV2,       "I/O Scheduler V2",             "IOKit.IOSchedulerV2"),
            (TweakID.KernelThermalGovernorV2,   "Thermal Governor V2",          "IOKit.ThermalGovernorV2"),
            (TweakID.KernelCPUGovernorPerf,     "CPU Governor Performance",     "XNU.CPUGovernorPerformance"),
            (TweakID.KernelNetworkStackV2,      "Network Stack V2",             "Darwin.NetworkStackV2"),
            (TweakID.KernelSecureMemoryV2,      "Secure Memory V2",             "XNU.SecureMemoryV2"),
            (TweakID.KernelIRQBalancing,        "IRQ Balancing",                "IOKit.IRQBalancing"),
            (TweakID.KernelZRAMEnabled,         "ZRAM Swap Compression",        "XNU.ZRAMEnabled"),
            (TweakID.KernelVMPressureOpt,       "VM Pressure Optimization",     "XNU.VMPressureOptimization"),
            (TweakID.KernelFileSystemCache,     "File System Cache V2",         "Darwin.FileSystemCacheV2"),
            (TweakID.KernelDiskSchedulerV2,     "Disk Scheduler V2",            "IOKit.DiskSchedulerV2"),
            (TweakID.KernelGraphicsDriverV2,    "Graphics Driver V2",           "IOKit.GraphicsDriverV2"),
            (TweakID.KernelAudioDriverV2,       "Audio Driver V2",              "IOKit.AudioDriverV2"),
            (TweakID.KernelUSBStackV2,          "USB Stack V2",                 "IOKit.USBStackV2"),
            (TweakID.KernelPowerManagementV2,   "Power Management V2",          "IOKit.PowerManagementV2"),
            (TweakID.KernelSecureEnclaveV2,     "Secure Enclave V2",            "XNU.SecureEnclaveV2"),
            (TweakID.KernelCryptoEngineV2,      "Crypto Engine V2",             "Darwin.CryptoEngineV2"),
            (TweakID.KernelSandboxV2,           "Sandbox V2",                   "Darwin.SandboxV2"),
            (TweakID.KernelSignalHandlerV2,     "Signal Handler V2",            "XNU.SignalHandlerV2"),
        ]:
            L.addWidget(_row(tid, name, f"mROS kernel flag: {flag}"))

        # ── mROS Exclusive V2 ─────────────────────────────────────────────────
        L.addWidget(_hdr("✦✦ mROS Exclusive — Beyond Any Phone"))
        L.addWidget(_div())
        for tid, name, desc in [
            (TweakID.MROSHolographicUI,     "Holographic Depth UI",
             "Full holographic depth layering across all SpringBoard surfaces (SpringBoard.HolographicDepthUI)."),
            (TweakID.MROSNeuralDisplay,     "Neural Display Optimization",
             "AI-driven per-frame display tuning — colour, brightness, sharpness (CoreDisplay.NeuralDisplayOptimization)."),
            (TweakID.MROSQuantumSync,       "Quantum Sync Renderer",
             "Frame-perfect synchronised rendering pipeline (UIKit.QuantumSyncRenderer)."),
            (TweakID.MROSBioMetricAura,     "BiometricKit Aura Display",
             "Biometric-ambient reactive display effects (BiometricKit.AuraDisplay)."),
            (TweakID.MROSChronoEngine,      "Chrono Time-Aware UI",
             "Time-of-day adaptive UI morphing engine (SpringBoard.ChronoTimeAwareUI)."),
            (TweakID.MROSAdaptiveCortex,    "Adaptive Cortex V2",
             "On-device adaptive AI reshapes UI based on usage patterns (CoreML.AdaptiveCortexV2)."),
            (TweakID.MROSProximityAura,     "Proximity Aura Morph",
             "UI elements morph in response to proximity sensor data (SpringBoard.ProximityAuraMorph)."),
            (TweakID.MROSRetinalTrack,      "Retinal Tracking",
             "Eye-tracking UI adaptation layer via ARKit (ARKit.RetinalTracking)."),
            (TweakID.MROSAmbientEngine,     "Ambient Computing Mode",
             "Full ambient computing presence — always-on context layer (SpringBoard.AmbientComputingMode)."),
            (TweakID.MROSHyperThread,       "Hyper-Threaded Rendering",
             "Parallel-threaded UI composition pipeline (UIKit.HyperThreadedRendering)."),
            (TweakID.MROSCrystalClear,      "Crystal Clear Glass",
             "Next-gen ultra-transparent glass rendering mode (SpringBoard.CrystalClearGlass)."),
            (TweakID.MROSQuantumHaptics,    "Quantum Haptic Patterns",
             "Sub-millisecond haptic pattern quantisation (CoreHaptics.QuantumHapticPatterns)."),
            (TweakID.MROSNeuralKernel,      "Neural Kernel Optimizer",
             "Neural-network driven kernel task scheduler (XNU.NeuralKernelOptimizer)."),
            (TweakID.MROSCognitiveUI,       "Cognitive Computing UI",
             "Cognitive-layer UI prediction and pre-rendering (UIKit.CognitiveComputingUI)."),
            (TweakID.MROSDeepFusion,        "Deep Fusion Rendering",
             "Multi-frame deep fusion compositor for all UI surfaces (CoreImage.DeepFusionRendering)."),
            (TweakID.MROSSilverLining,      "Silver Lining Effect",
             "Metallic silver-lining edge highlight on all panels (SpringBoard.SilverLiningEffect)."),
            (TweakID.MROSMorphicUI,         "Morphic Interface System",
             "Fluid interface morphing between all UI states (UIKit.MorphicInterfaceSystem)."),
            (TweakID.MROSEchoEngine,        "Echo Resonance Haptics",
             "Resonance-echo layered haptic feedback engine (CoreHaptics.EchoResonanceHaptics)."),
            (TweakID.MROSDimensionalShift,  "Dimensional Shift Animation",
             "3D dimensional-shift transition animations across the OS (UIKit.DimensionalShiftAnim)."),
            (TweakID.MROSHyperCore,         "HyperCore Scheduler",
             "Hyper-optimised XNU task scheduling for maximum throughput (XNU.HyperCoreScheduler)."),
        ]:
            L.addWidget(_row(tid, name, desc))

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
        load_maxos_ui()
        load_maxos_apps()
        load_maxos_system()
        load_maxos_exclusive()
        load_maxos_haptics_ar()
        load_maxos_connectivity()
        load_maxos_cloud_health()
        load_maxos_wallet_home_focus()
        load_maxos_privacy_shortcuts_org()
        load_maxos_reminders_files()
        load_maxos_gaming_media()
        load_maxos_extended_apps()
        load_maxos_system_core()
        load_mros_kernel()
        load_mros_exclusive_v2()
        # sync checkboxes with pre-enabled state
        self._sync_checkboxes()
