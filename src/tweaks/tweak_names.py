from enum import Enum, auto

class TweakID(Enum):
    # misc pages
    PosterBoard = auto()
    Templates = auto()
    StatusBar = auto()
    Passcode = auto()
    CreateBRFolders = auto()

    # mga
    DynamicIsland = auto()
    SupportsDynamicIsland = auto()
    ModelName = auto()
    BootChime = auto()
    ChargeLimit = auto()
    CollisionSOS = auto()
    TapToWake = auto()
    CameraButton = auto()
    Parallax = auto()
    StageManager = auto()
    iPadOS = auto()
    iPadOSCacheData = auto()
    iPadApps = auto()
    Shutter = auto()
    FindMyFriends = auto()
    Pencil = auto()
    ActionButton = auto()
    InternalStorage = auto()
    InternalInstall = auto()
    SRD = auto()
    AOD = auto()
    AODVibrancy = auto()
    EnableLGLPM = auto()
    DisableLGLPM = auto()
    RdarFix = auto()

    # eligibility
    EUEnabler = auto()
    AIEligibility = auto()
    AIGestalt = auto()
    AIFeatureFlags = auto()
    AIFeatureFlagsUI = auto()
    SpoofModel = auto()
    SpoofHardware = auto()
    SpoofCPU = auto()

    # feature flags
    ClockAnim = auto()
    Lockscreen = auto()
    PhotoUI = auto()
    AI = auto()
    SolariumFFSwiftUI = auto()
    SolariumFFSpringBoard = auto()
    SolariumFFIconServices = auto()
    SolariumFFPhotos = auto()
    SolariumFFDocumentCamera = auto()
    SolariumFFAppleMediaServices = auto()
    SolariumFFSharing = auto()
    SolariumFFMail = auto()
    KioskMode = auto()

    # springboard
    LockScreenFootnote = auto()
    WatchOSCompatibility = auto()
    AirDropDisableTimeLimit = auto()
    SBDontLockAfterCrash = auto()
    SBDontDimOrLockOnAC = auto()
    SBHideLowPowerAlerts = auto()
    SBHideACPower = auto()
    SBNeverBreadcrumb = auto()
    SBShowSupervisionTextOnLockScreen = auto()
    AirplaySupport = auto()
    SBMinimumLockscreenIdleTime = auto()
    SBAlwaysShowSystemApertureInSnapshots = auto()
    HideDICompletely = auto()
    SBShowAuthenticationEngineeringUI = auto()
    UseFloatingTabBar = auto()

    # internal
    SBBuildNumber = auto()
    RTL = auto()
    LTR = auto()
    SBIconVisibility = auto()
    MetalForceHudEnabled = auto()
    iMessageDiagnosticsEnabled = auto()
    IDSDiagnosticsEnabled = auto()
    VCDiagnosticsEnabled = auto()
    AccessoryDeveloperEnabled = auto()
    KeyFlick = auto()

    DisableSecondsHand = auto()
    DisableSearchingWebsites = auto()
    ShowButtonHints = auto()

    AppStoreDebug = auto()
    NotesDebugMode = auto()
    BKDigitizerVisualizeTouches = auto()
    BKHideAppleLogoOnLaunch = auto()
    EnableWakeGestureHaptic = auto()
    PlaySoundOnPaste = auto()
    AnnounceAllPastes = auto()

    # liquid glass
    ForceSolariumFallback = auto()
    DisableSolarium = auto()
    IgnoreSolariumLinkedOnCheck = auto()
    NoLiquidClock = auto()
    NoLiquidDock = auto()
    DisableSpecularMotion = auto()
    DisableOuterRefraction = auto()
    DisableSolariumHDR = auto()

    # risky
    DisableOTAFile = auto()
    CustomResolution = auto()
    # daemons
    Daemons = auto()
    ClearScreenTimeAgentPlist = auto()

    # ── Liquid Glass & Siri – real tweaks ──────────────────────────────────

    # Siri (real Apple MDM managed-preference keys in com.apple.siri.plist)
    Siri2FloatingBubble = auto()    # AssistantEnabled
    Siri2AmbientMode = auto()       # VoiceTriggerEnabled
    Siri2VisualResponse = auto()    # UIAssistantEnabled
    Siri2NaturalVoice = auto()      # KeyboardEnabled
    Siri2OnScreenContext = auto()   # SiriProfanityFilter
    Siri2CallScreening = auto()     # AssistantAllowedForAnyLockscreen

    # Liquid Glass per-app extensions (FeatureFlagTweak → FeatureFlags/Global.plist)
    SolariumFFMessages = auto()
    SolariumFFMaps = auto()
    SolariumFFSafari = auto()
    SolariumFFSpotlight = auto()
    SolariumFFControlCenter = auto()
    SolariumFFNotifications = auto()
    SolariumFFWidgets = auto()
    SolariumFFMusic = auto()
    SolariumFFPodcasts = auto()
    SolariumFFPhone = auto()
    SolariumFFCalendar = auto()
    SolariumFFReminders = auto()
    SolariumFFNotes = auto()

    # Liquid Glass fine-tuning (GlobalPreferences)
    NoLiquidStatusBar = auto()
    NoLiquidNotifications = auto()
    SolariumHighContrast = auto()
    SolariumForceLightTint = auto()
    SolariumMaxBlur = auto()

    # SpringBoard tweaks (com.apple.springboard.plist managed preferences)
    SBAlwaysGlassHeaders = auto()
    SBExpandedDynamicIsland = auto()
    SBShowBatteryPercentageAlways = auto()
    SBHideHomeIndicator = auto()
    SBDisableParallaxEffect = auto()
    SBAlwaysShowClockDI = auto()

    # ── Audio Processing (FeatureFlagTweak → FeatureFlags/Global.plist) ──────
    AudioSpatialDefault = auto()
    AudioEnhancedSpeaker = auto()
    AudioPersonalizedSpatial = auto()
    AudioBackgroundSounds = auto()
    AudioHeadphoneAccom = auto()
    AudioLoudnessNorm = auto()
    AudioSoundEffectsEnabled = auto()
    AudioHapticsSync = auto()

    # ── maxregnerOS: SpringBoard UI Feature Flags ─────────────────────────────
    SBFFFloatingDock = auto()
    SBFFDenseHomeScreen = auto()
    SBFFAppSwitcherV2 = auto()
    SBFFGlassFolders = auto()
    SBFFLiveActivitiesPersistent = auto()
    SBFFAdaptiveGrid = auto()
    SBFFContextWidgets = auto()
    SBFFProximityAnimations = auto()
    SBFFLargeWidgetGrid = auto()
    SBFFDynamicBackground = auto()
    SBFFGlassIconShimmer = auto()
    SBFFPageIndicatorRedesign = auto()
    SBFFEnhancedAppLibrary = auto()
    SBFFGlassSectionDividers = auto()
    SBFFDebugUIOverlay = auto()

    # ── maxregnerOS: UIKit Feature Flags ─────────────────────────────────────
    UIKitFFGlassSheets = auto()
    UIKitFFPillButtons = auto()
    UIKitFFLargeNavHeaders = auto()
    UIKitFFSwipeBackV2 = auto()
    UIKitFFFloatingMenus = auto()
    UIKitFFCardLayouts = auto()
    UIKitFFRubberBandPhysics = auto()
    UIKitFFGlassAlerts = auto()
    UIKitFFCompactProgress = auto()
    UIKitFFHapticKeyboard = auto()
    UIKitFFEnhancedTextRendering = auto()
    UIKitFFDynamicColorAdaptation = auto()

    # ── maxregnerOS: Photos & Camera Feature Flags ────────────────────────────
    PhotosFFEnhancedEditing = auto()
    PhotosFFAIAlbums = auto()
    PhotosFFMemoriesV2 = auto()
    PhotosFFImprovedSearch = auto()
    CameraFFProResVideo = auto()
    CameraFFMacroPro = auto()
    CameraFFNightModePortrait = auto()
    CameraFFProRAWMax = auto()
    CameraFFCinematicV2 = auto()
    CameraFFQuantumHDR = auto()

    # ── maxregnerOS: Messages & FaceTime Feature Flags ────────────────────────
    MsgFFEnhancedSearch = auto()
    MsgFFEffectsV2 = auto()
    MsgFFCollaborativeSharing = auto()
    MsgFFRichLinksV2 = auto()
    FaceTimeFFPersonSegmentation = auto()
    FaceTimeFFReactionAnimations = auto()
    FaceTimeFFSharedPlaybackV2 = auto()
    FaceTimeFFSpatialAudioCall = auto()

    # ── maxregnerOS: Maps & Location Feature Flags ────────────────────────────
    MapsFFImmersiveView = auto()
    MapsFFARWalkDirections = auto()
    MapsFFOfflineEnhanced = auto()
    MapsFFRealtimeTrafficV2 = auto()
    MapsFF3DPlaceCards = auto()
    MapsFFElevationData = auto()

    # ── maxregnerOS: Safari & WebKit Feature Flags ────────────────────────────
    SafariFFEnhancedPrivacy = auto()
    SafariFFTabGroupsV2 = auto()
    SafariFFWebExtensionsAPI = auto()
    SafariFFStartPageRedesign = auto()
    SafariFFFloatingAddressBar = auto()
    SafariFFReaderModeV2 = auto()

    # ── maxregnerOS: Widgets & Live Activities Feature Flags ──────────────────
    WidgetFFInteractiveWidgets = auto()
    WidgetFFLargeFormat = auto()
    WidgetFFAnimatedWidgets = auto()
    LiveActFFPersistentMode = auto()
    LiveActFFGlassPresentation = auto()
    LiveActFFStandbyV2 = auto()

    # ── maxregnerOS: Lock Screen & Notifications Feature Flags ────────────────
    LockFFWidgetsV2 = auto()
    LockFFDepthEffectClock = auto()
    LockFFLiveWeatherBG = auto()
    LockFFAlwaysOnDisplayV2 = auto()
    NotifFFStackedBanners = auto()
    NotifFFGlassNotifications = auto()
    NotifFFQuickRepliesV2 = auto()
    NotifFFSummaryV2 = auto()

    # ── maxregnerOS: System Performance Feature Flags ─────────────────────────
    PerfFFEnhancedLowPower = auto()
    PerfFFBackgroundRefreshV2 = auto()
    PerfFFLowLatencyAudio = auto()
    PerfFFHardwareAcceleration = auto()
    PerfFFThermalStatusUI = auto()
    PerfFFMemoryPressureMonitor = auto()
    PerfFFProcessPriorityBoost = auto()
    PerfFFUltraLowLatencyInput = auto()

    # ── maxregnerOS Exclusive ─────────────────────────────────────────────────
    MaxOSGlassEverywhere = auto()
    MaxOSFluidMotionEngine = auto()
    MaxOSNeuralEngineBoost = auto()
    MaxOSProDisplayRendering = auto()
    MaxOSHyperSmoothScrolling = auto()
    MaxOSChromaticAberration = auto()
    MaxOSDepthSensingV2 = auto()
    MaxOSAmbientIntelligence = auto()
    MaxOSProHapticsEngine = auto()
    MaxOSDynamicIslandPro = auto()