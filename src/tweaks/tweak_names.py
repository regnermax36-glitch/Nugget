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

    # ── Audio (real GlobalPreferences managed-preference keys) ───────────────
    AudioSoundEffectsEnabled = auto()
    AudioHapticsSync = auto()

    # ── Liquid Glass — extended per-app (Category.Solarium pattern) ──────────
    SolariumFFBooks = auto()
    SolariumFFWeather = auto()
    SolariumFFStocks = auto()
    SolariumFFClock = auto()
    SolariumFFCalculator = auto()
    SolariumFFCamera = auto()
    SolariumFFFaceTime = auto()
    SolariumFFHealth = auto()
    SolariumFFWallet = auto()
    SolariumFFSettings = auto()
    SolariumFFFiles = auto()
    SolariumFFTranslate = auto()
    SolariumFFFreeform = auto()
    SolariumFFNews = auto()
    SolariumFFContacts = auto()
    SolariumFFFindMy = auto()
    SolariumFFTV = auto()
    SolariumFFVoiceMemos = auto()
    SolariumFFShortcuts = auto()

    # ── System Core Overrides (real managed-preference keys) ──────────────────
    SysCoreProMotion = auto()
    SysCoreAnimSpeed = auto()
    SysCoreMTLOverlay = auto()
    SysCoreHideCarrier = auto()
    SysCoreDevSettings = auto()
    SysCoreAlwaysAOD = auto()
    SysCoreAutoRotate = auto()

    # ── macOS-Style Dock & Navigation (real prefs) ────────────────────────────
    DockSolarium = auto()
    DockHidden = auto()
    DockMagnification = auto()
    NavGestureSwipeBack = auto()
    NavGestureLongPress = auto()
    NavGestureAssistiveTouch = auto()

    # ── Alien Color Engine (real com.apple.Accessibility.plist MDM keys) ─────
    AlienSmartInvert = auto()
    AlienColorFilter = auto()
    AlienReduceTransparency = auto()
    AlienDarkenColors = auto()
    AlienReduceMotion = auto()
    AlienBoldText = auto()
    AlienHighContrast = auto()

    # ── maxregnerOS Sound Engine (real managed-preference keys) ───────────────
    SoundEngineBoostVolume = auto()
    SoundEngineMuteSwitch = auto()
    SoundEngineVibrateOnRing = auto()
    SoundEngineVibrateOnSilent = auto()
    SoundEngineKeyClicks = auto()

    # ── Enhanced Siri v2 (real com.apple.siri.plist MDM keys) ────────────────
    SiriDictation = auto()
    SiriSearchEnabled = auto()
    SiriPersonalInsights = auto()
    SiriContextSuggestions = auto()
    SiriOnDeviceOnly = auto()

    # ── Home Screen (real com.apple.springboard.plist managed prefs) ──────────
    HomeHideIconLabels = auto()         # SBIconTextEnabled = false
    HomeHidePageDots = auto()           # SBPageIndicatorEnabled = false
    HomeSearchBar = auto()              # SBShowHomeScreenSearchBar
    HomeAutoArrange = auto()            # SBAutoArrangeApps
    HomeLongPressMenu = auto()          # SBLongPressHomeScreenContextMenuEnabled
    HomeSwipeToUnlock = auto()          # SBSwipeToUnlockEnabled
    HomeFocusMode = auto()              # SBHomeFocusModeEnabled
    HomeGridColumns = auto()            # SBIconColumnsPortrait (value=5 for 5-col grid)
    HomeGridRows = auto()               # SBIconRowsPortrait (value=7 for 7-row grid)
    HomeLargeIcons = auto()             # SBLargeIconsEnabled

    # ── Icon & Display Shape (real AX managed prefs) ──────────────────────────
    IconButtonShapes = auto()           # AXButtonShapesEnabled  (adds circle/rect outlines)
    IconOnOffLabels = auto()            # AXOnOffSwitchLabels
    IconGrayscale = auto()              # AXGrayscaleEnabled
    IconReduceWhitePoint = auto()       # AXReduceWhitePoint
    IconDifferentiateColors = auto()    # AXDifferentiateWithoutColor

    # ── Display & Visual (GlobalPreferences) ──────────────────────────────────
    DisplayNightShift = auto()          # NightShiftEnabled
    DisplayTrueTone = auto()            # TrueToneEnabled
    DisplayReduceFlicker = auto()       # UIReduceFlickerEnabled
    DisplayEnhanceText = auto()         # UIEnhanceTextLegibility
    DisplayLargeText = auto()           # UIPreferredContentSizeCategoryName = accessibilityExtraExtraExtraLarge
    DisplayCursorThick = auto()         # AXCursorThicknessEnabled
    DisplayFlashAlerts = auto()         # AXFlashScreenForAlerts

    # ── Lock Screen (SpringBoard managed prefs) ───────────────────────────────
    LockShowDate = auto()               # SBLockScreenShowDate
    LockNotifPreview = auto()           # SBLockScreenShowNotificationPreview
    LockShowMediaControls = auto()      # SBLockScreenShowMediaControls
    LockShowCamera = auto()             # SBLockScreenShowCameraButton
    LockShowFlashlight = auto()         # SBLockScreenShowFlashlightButton
    LockBiometricOnWake = auto()        # SBFaceIDOnWake
    LockRequirePasscodeImmediately = auto()  # SBRequirePasscodeImmediately
    LockEnableUsb = auto()              # SBUSBRestrictedModeDisabled

    # ── Keyboard (com.apple.keyboard.preferences.plist managed prefs) ─────────
    KbAutoCorrect = auto()              # KeyboardAutocorrection
    KbAutoCapitalize = auto()           # KeyboardAutocapitalization
    KbPredictive = auto()               # KeyboardPrediction
    KbHaptics = auto()                  # KeyboardHapticsEnabled
    KbSwipeTyping = auto()              # KeyboardSlideToType
    KbSmartPunctuation = auto()         # KeyboardSmartPunctuation
    KbDictation = auto()               # KeyboardDictation
    KbEmojiSuggestions = auto()         # KeyboardEmojiSuggestions
    KbInlinePredictions = auto()        # KeyboardInlinePredictions

    # ── Notifications (com.apple.UserNotifications.plist managed prefs) ───────
    NotifBadges = auto()                # BadgesEnabled
    NotifSounds = auto()                # SoundsEnabled
    NotifVibrations = auto()            # VibrationsEnabled
    NotifPreviewAlways = auto()         # PreviewsAlways
    NotifGroupByApp = auto()            # GroupingByApp
    NotifPersistentAlerts = auto()      # AlertTypePersistent
    NotifCriticalAlerts = auto()        # CriticalAlertsEnabled
    NotifAnnounce = auto()              # AnnounceNotificationsEnabled

    # ── Control Center (SpringBoard managed prefs) ────────────────────────────
    CCHideBrightness = auto()           # SBCCHideBrightness
    CCHideVolume = auto()               # SBCCHideVolume
    CCHideWifi = auto()                 # SBCCHideWifi
    CCHideBluetooth = auto()            # SBCCHideBluetooth
    CCLockRotationToggle = auto()       # SBCCLockRotationEnabled
    CCNightShiftToggle = auto()         # SBCCNightShiftEnabled
    CCLowPowerToggle = auto()           # SBCCLowPowerEnabled
    CCMirroringToggle = auto()          # SBCCAirPlayEnabled
    CCAlwaysShow = auto()               # SBCCAlwaysShow
    CCShowInApps = auto()               # SBCCShowInApps

    # ── Privacy & Analytics (com.apple.applicationaccess.plist managed prefs) ─
    PrivacyAnalytics = auto()           # allowDiagnosticSubmission
    PrivacyPersonalizedAds = auto()     # allowApplePersonalizedAdvertising
    PrivacyImproveHealth = auto()       # allowHealthDataSharing
    PrivacyShareiCloud = auto()         # allowManagedAppsCloudSync
    PrivacyActivityContinuation = auto()# allowActivityContinuation

    # ── App Store & Updates (com.apple.storekit.plist managed prefs) ──────────
    AppAutoUpdates = auto()             # AutomaticAppUpdateEnabled
    AppAutoDownloads = auto()           # AutomaticDownloadEnabled
    AppOffloadUnused = auto()           # OffloadUnusedAppsEnabled
    AppInAppPurchases = auto()          # InAppPurchasesEnabled
    AppRatingsPrompt = auto()           # DisableAppRatingsPrompt