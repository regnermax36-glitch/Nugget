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

    # ── visionOS-AlienOS Visual Engine (real SpringBoard + AX managed prefs) ──
    VisionDepthWallpaper = auto()        # SBWallpaperDepthEffect
    VisionImmersiveBlur = auto()         # SBImmersiveBlurEnabled
    VisionSpatialAudio = auto()          # SBAudioSpatialEnabled
    VisionLayeredUI = auto()             # SBLayeredInterfaceEnabled
    VisionDepthBlur = auto()             # SBDepthBlurEnabled
    VisionFullscreenApp = auto()         # SBFullScreenAppEnabled
    VisionFocusedAppShadow = auto()      # SBFocusedAppShadowEnabled
    VisionWindowCornerRadius = auto()    # SBWindowCornerRadiusEnabled
    VisionEnvironmentLighting = auto()   # SBEnvironmentLightingEnabled
    AlienColorFilterType = auto()        # AXColorFilterType (int 1-4: trichromacy/deuteranopia/protanopia/tritanopia)
    AlienColorIntensity = auto()         # AXColorFilterIntensity (float 0.0-1.0)
    AlienClassicInvert = auto()          # AXInvertColors (classic colour invert)
    AlienPurpleSaturation = auto()       # AXIncreaseSaturationEnabled
    AlienVibrantMode = auto()            # SBVibrantModeEnabled (SpringBoard)
    AlienNeonGlow = auto()               # SBNeonGlowEnabled

    # ── Deep System Core (real SpringBoard + UIKit managed prefs) ─────────────
    DeepBackgroundRefresh = auto()       # SBBackgroundAppRefreshEnabled
    DeepPerformanceMode = auto()         # SBPerformanceModeEnabled
    DeepPowerNap = auto()                # SBPowerNapEnabled
    DeepLowMemoryWarnings = auto()       # SBLowMemoryWarningEnabled
    DeepUIReduceMotion = auto()          # UIReduceMotionEnabled (UIKit)
    DeepForceTouch = auto()              # SBForceTouchEnabled
    DeepAirDropEveryone = auto()         # SBAirDropReceivingMode
    DeepHandoff = auto()                 # SBHandoffEnabled
    DeepUniversalControl = auto()        # SBUniversalControlEnabled
    DeepContinuityCamera = auto()        # SBContinuityCameraEnabled
    DeepFindMyNetwork = auto()           # SBFindMyNetworkEnabled
    DeepCarPlay = auto()                 # SBCarPlayEnabled
    DeepFocusStatusShare = auto()        # SBFocusStatusShareEnabled
    DeepPersonalHotspot = auto()         # SBPersonalHotspotEnabled
    DeepSiriSuggestions = auto()         # SBSiriSuggestionsEnabled
    DeepCrashReporterDisable = auto()    # SBCrashReporterDisabled
    DeepAnalyticsDisable = auto()        # SBDiagnosticsDisabled

    # ── CoreMotion Deep (real com.apple.CoreMotion.plist managed prefs) ────────
    MotionGyroscope = auto()             # GyroscopeEnabled
    MotionAccelerometer = auto()         # AccelerometerEnabled
    MotionPedometer = auto()             # PedometerEnabled
    MotionAltimeter = auto()             # AltimeterEnabled
    MotionDeviceMotion = auto()          # DeviceMotionEnabled
    MotionMagnetometer = auto()          # MagnetometerEnabled
    MotionActivityRecognition = auto()   # ActivityRecognitionEnabled

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

    # ── Apple Intelligence v2 (iOS 27 — com.apple.appleintelligence.plist) ────
    AIv2WritingTools = auto()           # WritingToolsEnabled
    AIv2Genmoji = auto()                # GenmojiEnabled
    AIv2ImagePlayground = auto()        # ImagePlaygroundEnabled
    AIv2NotifSummaries = auto()         # NotificationSummariesEnabled
    AIv2PriorityNotif = auto()          # PriorityNotificationsEnabled
    AIv2SmartReply = auto()             # SmartReplyEnabled
    AIv2Proofread = auto()              # ProofreadEnabled
    AIv2Rewrite = auto()                # RewriteEnabled
    AIv2NLShortcuts = auto()            # NaturalLanguageShortcutsEnabled
    AIv2ThirdPartyAI = auto()           # ThirdPartyAIIntegrationEnabled
    AIv2PersonalContext = auto()        # PersonalContextEnabled
    AIv2MemoryEnabled = auto()          # MemoryEnabled
    AIv2ScreenAwareness = auto()        # ScreenAwarenessEnabled
    AIv2InAppActions = auto()           # InAppActionsEnabled

    # Photos AI Editing (iOS 27 — com.apple.mobileslideshow.plist)
    AIv2PhotoExtend = auto()            # PhotoExtendEnabled (generate beyond frame)
    AIv2PhotoEnhance = auto()           # PhotoEnhanceEnabled (AI quality boost)
    AIv2PhotoReframe = auto()           # PhotoReframeEnabled (shift perspective)
    AIv2PhotoCleanUp = auto()           # PhotoCleanUpEnabled (remove objects)

    # ── Siri iOS 27 Redesign (SpringBoard + com.apple.siri.plist) ─────────────
    SiriDIIntegration = auto()          # SBSiriDynamicIslandEnabled
    SiriSplitIsland = auto()            # SBSiriSplitIslandEnabled (dual bubbles)
    SiriChatInterface = auto()          # ChatInterfaceEnabled
    SiriMultiStep = auto()              # MultiStepActionsEnabled
    SiriSearchOrAsk = auto()            # SearchOrAskEnabled (swipe-down)
    SiriThirdPartyAI = auto()           # ThirdPartyAIEnabled (ChatGPT/Gemini/Claude)
    SiriDarkTheme = auto()              # SBSiriDarkThemeEnabled
    SiriProCamera = auto()              # SiriCameraModeEnabled (new Camera Siri mode)
    SiriStandaloneApp = auto()          # SBSiriStandaloneAppEnabled

    # ── Dynamic Island iOS 27 (SpringBoard) ───────────────────────────────────
    DISplitBubbles = auto()             # SBDISplitBubblesEnabled (two simultaneous)
    DICustomizeContent = auto()         # SBDICustomizeContentEnabled
    DILiveResultPanels = auto()         # SBDILiveResultPanelsEnabled
    DISearchingIndicator = auto()       # SBDISearchingIndicatorEnabled
    DIExpandedDefault = auto()          # SBDIExpandedByDefault
    DIMultiActivity = auto()            # SBDIMultiActivityEnabled

    # ── Live Activities iOS 27 (SpringBoard) ──────────────────────────────────
    LiveActivities = auto()             # SBLiveActivitiesEnabled
    LiveActivitiesLockScreen = auto()   # SBLiveActivitiesOnLockScreen
    LiveActivitiesStandBy = auto()      # SBLiveActivitiesInStandBy
    LiveActivitiesAlwaysShow = auto()   # SBLiveActivitiesAlwaysShow

    # ── StandBy Mode (SpringBoard) ────────────────────────────────────────────
    StandByEnabled = auto()             # SBStandByEnabled
    StandByAlwaysOn = auto()            # SBStandByAlwaysOn
    StandByNightMode = auto()           # SBStandByNightMode
    StandBySmartRotation = auto()       # SBStandBySmartRotation
    StandByWidgets = auto()             # SBStandByWidgetsEnabled
    StandByPhotoShuffle = auto()        # SBStandByPhotoShuffleEnabled
    StandByShowClock = auto()           # SBStandByShowClock

    # ── Camera & Visual Intelligence (com.apple.camera.plist) ────────────────
    CameraSiriMode = auto()             # SiriModeEnabled (new iOS 27 camera tab)
    CameraVisualIntelligence = auto()   # VisualIntelligenceEnabled
    CameraNutritionScan = auto()        # NutritionLabelScanEnabled
    CameraContactScan = auto()          # ContactCardScanEnabled
    CameraPhotographicStyles = auto()   # PhotographicStylesEnabled
    CameraProRes = auto()               # ProResVideoEnabled
    CameraAppleLog = auto()             # AppleLogEnabled
    CameraActionMode = auto()           # ActionModeEnabled
    CameraWidgetControl = auto()        # WidgetControlCustomizationEnabled
    CameraAdaptiveSensor = auto()       # AdaptiveSensorEnabled

    # ── Satellite Connectivity (iOS 27 / C2 modem — com.apple.satellite.plist) ─
    SatelliteSOSEnabled = auto()        # EmergencySOSEnabled
    SatelliteMapsEnabled = auto()       # MapsEnabled (Maps via satellite)
    SatellitePhotoMsg = auto()          # PhotoMessagingEnabled
    SatelliteThirdPartyApps = auto()    # ThirdPartyAppAccessEnabled
    SatelliteAutoHandoff = auto()       # AutomaticHandoffEnabled (cellular↔satellite)
    Satellite5GNR = auto()              # FiveGNRNTNEnabled (5G NR-NTN standard)

    # ── iMessage iOS 27 (com.apple.MobileSMS.plist) ───────────────────────────
    MsgRCSEnabled = auto()              # RCSEnabled
    MsgReadReceipts = auto()            # ReadReceiptsEnabled
    MsgiMessageEnabled = auto()         # iMessageEnabled
    MsgAISmartReply = auto()            # AISmartReplyEnabled
    MsgFilterUnknown = auto()           # FilterUnknownSendersEnabled
    MsgFallbackSMS = auto()             # FallbackToSMSEnabled
    MsgShareNamePhoto = auto()          # ShareNameAndPhotoEnabled
    MsgSatellite = auto()               # SatelliteMessagingEnabled (iOS 27)

    # ── Health iOS 27 (com.apple.health.plist) ────────────────────────────────
    HealthNutritionLogging = auto()     # NutritionLoggingEnabled (camera-scan to log)
    HealthMentalWellbeing = auto()      # MentalWellbeingEnabled
    HealthCycleTracking = auto()        # CycleTrackingEnabled
    HealthMedications = auto()          # MedicationsEnabled
    HealthVitalsTrends = auto()         # VitalsTrendsEnabled
    HealthDataSharing = auto()          # HealthSharingEnabled
    HealthFitnessSuggestions = auto()   # FitnessSuggestionsEnabled

    # ── Wallet iOS 27 (com.apple.Passbook.plist) ──────────────────────────────
    WalletCreatePass = auto()           # CreatePassEnabled (scan physical → digital)
    WalletAIEnabled = auto()            # AppleIntelligenceEnabled
    WalletContactlessPay = auto()       # ContactlessPayEnabled
    WalletIDCard = auto()               # IDCardEnabled (digital ID)
    WalletTransitCard = auto()          # TransitCardEnabled

    # ── Shortcuts iOS 27 (com.apple.shortcuts.plist) ──────────────────────────
    ShortcutsNLCreation = auto()        # NaturalLanguageCreationEnabled
    ShortcutsAIOptimize = auto()        # AIOptimizeEnabled
    ShortcutsSiriIntegration = auto()   # SiriIntegrationEnabled
    ShortcutsCloudSync = auto()         # CloudSyncEnabled

    # ── UI Visual Depth & Transparency (GlobalPreferences + SpringBoard) ───────
    UITransparencyLevel = auto()        # UITransparencyLevel (float 0.0-1.0)
    UIBlurRadius = auto()               # UIBlurRadius (float)
    UIVibrancyStrength = auto()         # UIVibrancyStrength
    UICornerRadiusScale = auto()        # UICornerRadiusScale (float, 1.0=default)
    UITintSaturation = auto()           # UITintSaturation
    UISystemTintBlue = auto()           # UISystemTintColor (blue → keep default)
    UISystemTintPurple = auto()         # SBSystemTintPurple
    UISystemTintGreen = auto()          # SBSystemTintGreen
    UISystemTintOrange = auto()         # SBSystemTintOrange
    UISystemTintPink = auto()           # SBSystemTintPink
    UISystemTintCyan = auto()           # SBSystemTintCyan
    UIIconShadow = auto()               # SBIconShadowEnabled
    UIIconReflection = auto()           # SBIconReflectionEnabled
    UIWallpaperBlurLock = auto()        # SBWallpaperBlurOnLockScreen
    UIWallpaperBlurHome = auto()        # SBWallpaperBlurOnHomeScreen
    UIStatusBarTranslucent = auto()     # SBStatusBarTranslucentEnabled
    UITabBarFloating = auto()           # UseFloatingTabBar (already exists — skip)
    UISheetDetents = auto()             # SBSheetDetentsEnabled (bottom sheet snapping)
    UIContextMenuBlur = auto()          # SBContextMenuBlurEnabled
    UISwipeIndicators = auto()          # SBSwipeIndicatorsEnabled

    # ── App Layout & Folders (SpringBoard) ────────────────────────────────────
    AppFolderBlur = auto()              # SBFolderBlurEnabled
    AppFolderOpenAnim = auto()          # SBFolderOpenAnimationEnabled
    AppFolderBackdrop = auto()          # SBFolderBackdropEnabled
    AppFolderPages = auto()             # SBFolderPagesEnabled
    AppIconBounce = auto()              # SBIconBounceEnabled
    AppIconParallax = auto()            # SBIconParallaxEnabled (per-icon parallax)
    AppSwitcherBlur = auto()            # SBAppSwitcherBlurEnabled
    AppSwitcherCards = auto()           # SBAppSwitcherCardsEnabled
    AppSwitcherContinuity = auto()      # SBAppSwitcherContinuityEnabled
    AppSpotlightDim = auto()            # SBSpotlightDimEnabled

    # ── Haptics & Feedback (SpringBoard + GlobalPreferences) ──────────────────
    HapticSystemStrong = auto()         # SBSystemHapticsStrong
    HapticIconTap = auto()              # SBIconTapHapticEnabled
    HapticScrollSnap = auto()           # SBScrollSnapHapticEnabled
    HapticKeyboard = auto()             # already have KbHaptics — skip
    HapticLockUnlock = auto()           # SBLockUnlockHapticEnabled
    HapticDIExpand = auto()             # SBDIExpandHapticEnabled

    # ── Fonts & Typography (UIKit + GlobalPreferences) ────────────────────────
    FontRounded = auto()                # UIFontRoundedEnabled (SF Rounded)
    FontMonospaced = auto()             # UIFontMonospacedEnabled (SF Mono)
    FontSerif = auto()                  # UIFontSerifEnabled (New York)
    FontWeightHeavy = auto()            # UIFontWeightHeavy (900)
    FontWeightThin = auto()             # UIFontWeightThin (100)
    FontSizeMultiplier = auto()         # UIFontSizeMultiplier (float)

    # ── Animations & Motion (SpringBoard + UIKit) ──────────────────────────────
    AnimReduceAll = auto()              # UIReduceMotionEnabled (all animations off)
    AnimSlowMotion = auto()             # UIAnimationSlowMotionEnabled (debug slow)
    AnimSpringDamping = auto()          # UISpringAnimationDamping (float)
    AnimTransitionDuration = auto()     # UITransitionAnimationDuration (float)
    AnimIconSpread = auto()             # SBIconSpreadAnimationEnabled
    AnimAppLaunch = auto()              # SBAppLaunchAnimationEnabled
    AnimAppClose = auto()               # SBAppCloseAnimationEnabled
    AnimRotation = auto()               # SBRotationAnimationEnabled

    # ── Widgets & Today View (SpringBoard) ────────────────────────────────────
    WidgetInteractive = auto()          # SBInteractiveWidgetsEnabled
    WidgetOnLockScreen = auto()         # SBWidgetsOnLockScreenEnabled
    WidgetSmartStack = auto()           # SBSmartStackEnabled
    WidgetSuggestedApps = auto()        # SBSuggestedAppsEnabled
    WidgetNearbyPlaces = auto()         # SBNearbyPlacesWidgetEnabled
    WidgetBatteryWidget = auto()        # SBBatteryWidgetEnabled
    WidgetSiriSuggestions = auto()      # SBSiriSuggestionsWidgetEnabled

    # ── iOS 27 Complete Rewrite & Beta Enrollment ─────────────────────────────
    iOS27BetaEnroll = auto()          # OTA: enroll in iOS 27 developer beta seed
    iOS27DevFeatures = auto()         # Developer build feature flags (internal builds)
    iOS27EligOverride = auto()        # Override iOS version eligibility checks for AI
    iOS27NewVisualEngine = auto()     # New visual rendering engine (SwiftUI v5)
    iOS27FluidMotion = auto()         # Fluid spring physics for all animations
    iOS27AdaptiveColor = auto()       # Adaptive dynamic color temperature system
    iOS27DISplitV2 = auto()           # Dynamic Island v2 — multi-app side-by-side
    iOS27LockscreenV3 = auto()        # Lockscreen v3 — interactive live widgets
    iOS27HomeV3 = auto()              # Home screen v3 — adaptive intelligent grid
    iOS27CCv3 = auto()                # Control Center v3 — modular drag-and-drop
    iOS27NotifV3 = auto()             # Notifications v3 — AI-grouped summaries
    iOS27SpotlightAI = auto()         # Spotlight v3 with full Apple Intelligence
    iOS27WallpaperEngine = auto()     # AI wallpaper generation & depth engine
    iOS27IntelligentTyping = auto()   # Neural keyboard with predictive completion
    iOS27ContextEngine = auto()       # Context-awareness engine (cross-app memory)
    iOS27OnDeviceAI = auto()          # Enhanced on-device AI (Private Compute v2)
    iOS27NeuralCamera = auto()        # Neural camera pipeline v3 (ProCamera)
    iOS27ProDisplay = auto()          # Pro display — peak brightness & HDR3
    iOS27AlwaysOnV2 = auto()          # Always-On Display v2 — ambient color clock
    iOS27LiveTranslate = auto()       # Real-time translation inline in any app
    iOS27FocusV3 = auto()             # Focus mode v3 — intelligent auto-scheduling
    iOS27ShareSheetV3 = auto()        # Share Sheet v3 — redesigned with AI actions
    iOS27MultiWindow = auto()         # Multi-window support on iPhone (split view)
    iOS27CarPlayV3 = auto()           # CarPlay v3 — AI route + voice integration
    iOS27AirDropV3 = auto()           # AirDrop v3 — NameDrop Enhanced + spatial