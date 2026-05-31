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

    # home screen & dock  (SpringBoard managed preferences — verified in SB binary)
    HomeScreenRotation = auto()      # SBAllowHomeScreenRotation
    HideIconLabels = auto()          # SBHideHomeScreenIconLabels
    HideDockBackground = auto()      # SBHideDockBackground
    AnimationSpeedFast = auto()      # UIAnimationDragCoefficient = 0.5  (well documented)
    AnimationSpeedSlow = auto()      # UIAnimationDragCoefficient = 10.0 (slow-motion debug)
    HideNotificationBadges = auto()  # SBHideIconBadges
    DisableAppSwitcherBlur = auto()  # SBDisableAppSwitcherBlurBackground
    ShowBatteryPercentage = auto()   # SBShowBatteryPercentage (status bar)

    # sound (SpringBoard / UIKit managed preferences)
    SoundKeyboardFeedback = auto()   # UIKeyboardSoundFeedback   (UIKit)
    SoundScreenshotDisable = auto()  # SBCaptureControllerScreenCaptureSoundDisabled
    SoundChargeAlert = auto()        # SBChargingReminderSoundEnabled
    SoundSlowChargeAlert = auto()    # SBSlowChargeAlertSoundEnabled
    SoundRingerHapticSync = auto()   # SBRingerAudioVibrateSync
    SoundVolumeHUD = auto()          # SBVolumeHUDSoundEnabled

    # cellular & modem  (com.apple.coretelephony managed preferences)
    CellularDataRoaming = auto()     # DataRoamingEnabled
    Cellular5G = auto()              # 5GEnabled
    CellularVoLTE = auto()           # VoLTEEnabled
    CellularWiFiCalling = auto()     # WiFiCallingEnabled
    CellularHDVoice = auto()         # HDVoiceEnabled
    CellularLTE = auto()             # LTEEnabled

    # Safari & networking  (com.apple.mobilesafari managed preferences)
    SafariWebInspector = auto()      # WebKitDeveloperExtrasEnabled
    SafariAllowHTTP = auto()         # AllowHTTP
    SafariBlockPopups = auto()       # BlockPopups
    SafariDoNotTrack = auto()        # DNTEnabled
    SafariFullURL = auto()           # ShowFullURL
    SafariFraudWarning = auto()      # WarnAboutFraudulentWebsites
    SafariJavaScript = auto()        # WebKitJavaScriptEnabled
    SafariSearchSuggest = auto()     # SuppressSearchSuggestions (inverted)
    SafariHTTP3 = auto()             # WebKitNetworkHTTP3Enabled
    SafariPrivateRelay = auto()      # iCloudPrivateRelayEnabled
    SafariDoH = auto()               # WebKitDNSOverHTTPSEnabled
    SafariECH = auto()               # WebKitEncryptedClientHelloEnabled

    # 6G & advanced cellular  (com.apple.coretelephony managed preferences)
    Cell6GEnabled = auto()           # 6GEnabled  (future-facing, IMT-2030)
    CellmmWave = auto()              # mmWaveEnabled  (5G FR2 / mmWave bands)
    CellCarrierAgg = auto()          # CarrierAggregationEnabled
    CellStandalone5G = auto()        # Standalone5GEnabled  (SA vs NSA NR)
    CellNRDualConnectivity = auto()  # NRDualConnectivityEnabled
    CellAdvancedMIMO = auto()        # AdvancedMIMOEnabled  (Massive MIMO)
    CellLowLatencyMode = auto()      # LowLatencyModeEnabled  (URLLC slicing)

    # risky
    DisableOTAFile = auto()
    CustomResolution = auto()
    # daemons
    Daemons = auto()
    ClearScreenTimeAgentPlist = auto()
