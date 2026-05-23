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

    # ── iOS 27 Concept & Siri 2.0 ──────────────────────────────────────────

    # Siri 2.0 UI feature flags
    Siri2FloatingBubble = auto()
    Siri2AmbientMode = auto()
    Siri2VisualResponse = auto()
    Siri2NaturalVoice = auto()
    Siri2OnScreenContext = auto()
    Siri2CallScreening = auto()
    Siri2PersonalHistory = auto()
    Siri2VisionProStyle = auto()

    # iOS 27 home screen feature flags
    iOS27LargeWidgets = auto()
    iOS27HomeScreenRedesign = auto()
    iOS27AppLibraryRedesign = auto()
    iOS27ContextMenuRedesign = auto()
    iOS27AppSwitcherRedesign = auto()

    # iOS 27 system UI feature flags
    iOS27CCRedesign = auto()
    iOS27NotificationsRedesign = auto()
    iOS27LockScreenRedesign = auto()
    iOS27StatusBarRedesign = auto()
    iOS27ShareSheetRedesign = auto()

    # Liquid Glass 2.0 per-app extensions (feature flags)
    SolariumFFMessages = auto()
    SolariumFFMaps = auto()
    SolariumFFSafari = auto()
    SolariumFFSpotlight = auto()
    SolariumFFControlCenter = auto()
    SolariumFFNotifications = auto()
    SolariumFFWidgets = auto()

    # Liquid Glass fine-tuning (plist)
    NoLiquidStatusBar = auto()
    NoLiquidNotifications = auto()
    SolariumHighContrast = auto()
    SolariumForceLightTint = auto()
    SolariumMaxBlur = auto()

    # SpringBoard iOS 27 plist tweaks
    SBAlwaysGlassHeaders = auto()
    SBExpandedDynamicIsland = auto()
    SBShowWeatherLockScreen = auto()
    SBEnhancedHaptics = auto()
    SBShowBatteryPercentageAlways = auto()
    SBHideHomeIndicator = auto()
    SBDisableParallaxEffect = auto()

    # ── iOS 27 Concept batch 2 ─────────────────────────────────────────────

    # Siri 2.0 Advanced
    Siri2MultiModal = auto()
    Siri2OfflineMode = auto()
    Siri2ProactiveCards = auto()
    Siri2AppIntents2 = auto()
    Siri2LiveTranslation = auto()

    # iOS 27 Typography & Fonts
    iOS27DynamicType2 = auto()
    iOS27NewSystemFont = auto()
    iOS27BoldUIElements = auto()
    iOS27LargeHeaderStyle = auto()
    iOS27CompactLabels = auto()

    # iOS 27 Animations
    iOS27SpringAnimations = auto()
    iOS27MorphTransitions = auto()
    iOS27ElasticBounce = auto()
    iOS27ZoomTransitions = auto()
    iOS27GlassReveal = auto()
    iOS27ReducedMotionAlt = auto()

    # iOS 27 Colors & Appearance
    iOS27VividColors = auto()
    iOS27DynamicColors = auto()
    iOS27TintEverywhere = auto()
    iOS27TrueBlack = auto()
    iOS27ColorizedGlass = auto()
    iOS27MaterialVariant2 = auto()

    # iOS 27 Keyboard
    iOS27KeyboardRedesign = auto()
    iOS27KeyboardGlass = auto()
    iOS27SmartPrediction = auto()
    iOS27KeyboardHaptics = auto()

    # iOS 27 Multitasking
    iOS27StagedMultitasking = auto()
    iOS27FloatingApps = auto()
    iOS27PiPEnhancements = auto()
    iOS27SplitViewIPhone = auto()

    # iOS 27 Photos & Camera
    iOS27PhotosRedesign = auto()
    iOS27CameraRedesign = auto()
    iOS27SmartAlbums2 = auto()
    iOS27CinematicCapture = auto()
    iOS27ProRAWEnhanced = auto()

    # iOS 27 Privacy & Security
    iOS27PrivacyDashboard2 = auto()
    iOS27AppPrivacyReport2 = auto()
    iOS27BiometricEnhanced = auto()
    iOS27LockdownModeLite = auto()

    # Liquid Glass 3.0 – more apps
    SolariumFFMusic = auto()
    SolariumFFPodcasts = auto()
    SolariumFFPhone = auto()
    SolariumFFCalendar = auto()
    SolariumFFReminders = auto()
    SolariumFFNotes = auto()

    # SpringBoard iOS 27 Advanced
    SBSmartStackRedesign = auto()
    SBIconBadgeRedesign = auto()
    SBTransparentFolders = auto()
    SBAlwaysShowClockDI = auto()
    SBFocusFiltersRedesign = auto()