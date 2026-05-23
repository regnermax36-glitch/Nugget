from .tweaks import tweaks, TweakID
from .tweak_classes import MobileGestaltTweak, MobileGestaltMultiTweak, MobileGestaltPickerTweak, MobileGestaltCacheDataTweak, RdarFixTweak, FeatureFlagTweak, BasicPlistTweak, FileLocation, AdvancedPlistTweak, NullifyFileTweak
from .eligibility_tweak import EligibilityTweak, AITweak
from src.devicemanagement.constants import Device, Version

def get_mobilegestalt_tweaks() -> dict:
    return {
        TweakID.DynamicIsland: MobileGestaltPickerTweak("oPeik/9e8lQWMszEjbPzng", subkey="ArtworkDeviceSubType", values=[2436, 2556, 2796, 2622, 2868, 2736]),
        TweakID.SupportsDynamicIsland: MobileGestaltTweak("YlEtTtHlNesRBMal1CqRaA"),
        TweakID.ModelName: MobileGestaltTweak("oPeik/9e8lQWMszEjbPzng", subkey="ArtworkDeviceProductDescription", value=""),
        TweakID.BootChime: MobileGestaltTweak("QHxt+hGLaBPbQJbXiUJX3w"),
        TweakID.EnableLGLPM: MobileGestaltTweak("SAGvsp6O6kAQ4fEfDJpC4Q"),
        TweakID.DisableLGLPM: MobileGestaltTweak("SAGvsp6O6kAQ4fEfDJpC4Q", value=0),
        TweakID.ChargeLimit: MobileGestaltTweak("37NVydb//GP/GrhuTN+exg"),
        TweakID.CollisionSOS: MobileGestaltTweak("HCzWusHQwZDea6nNhaKndw"),
        TweakID.TapToWake: MobileGestaltTweak("yZf3GTRMGTuwSV/lD7Cagw"),
        TweakID.CameraButton: MobileGestaltMultiTweak({"CwvKxM2cEogD3p+HYgaW0Q": 1, "oOV1jhJbdV3AddkcCg0AEA": 1}),
        TweakID.Parallax: MobileGestaltTweak("UIParallaxCapability", value=0),
        TweakID.StageManager: MobileGestaltTweak("qeaj75wk3HF4DwQ8qbIi7g", value=1),
        TweakID.iPadOS: MobileGestaltMultiTweak({"mG0AnH/Vy1veoqoLRAIgTA": 1, "UCG5MkVahJxG1YULbbd5Bg": 1, "ZYqko/XM5zD3XBfN5RmaXA": 1, "nVh/gwNpy7Jv1NOk00CMrw": 1, "uKc7FPnEO++lVhHWHFlGbQ": 1}),
        TweakID.iPadOSCacheData: MobileGestaltCacheDataTweak(slice_start=1616, slice_length=200),
        TweakID.iPadApps: MobileGestaltTweak("9MZ5AdH43csAUajl/dU+IQ", value=[1, 2]),
        TweakID.Shutter: MobileGestaltMultiTweak({"h63QSdBCiT/z0WU6rdQv6Q": "US", "zHeENZu+wbg7PUprwNwBWg": "LL/A"}),
        TweakID.Pencil: MobileGestaltTweak("yhHcB0iH0d1XzPO/CFd3ow"),
        TweakID.ActionButton: MobileGestaltTweak("cT44WE1EohiwRzhsZ8xEsw"),
        TweakID.InternalStorage: MobileGestaltTweak("LBJfwOEzExRxzlAnSuI7eg"),
        TweakID.InternalInstall: MobileGestaltTweak("EqrsVvjcYDdxHBiQmGhAWw"),
        TweakID.SRD: MobileGestaltTweak("XYlJKKkj2hztRP1NWWnhlw"),
        TweakID.AOD: MobileGestaltMultiTweak(
                                {"2OOJf1VhaM7NxfRok3HbWQ": 1, "j8/Omm6s1lsmTDFsXjsBfA": 1}),
        TweakID.AODVibrancy: MobileGestaltTweak("ykpu7qyhqFweVMKtxNylWA")
    }

def load_rdar_fix(dev: Device):
    if TweakID.RdarFix in tweaks:
        return
    tweaks.update({TweakID.RdarFix: RdarFixTweak()})
    if dev != None:
        # load settings
        tweaks[TweakID.RdarFix].get_rdar_mode(dev.model)

def load_mobilegestalt(dev: Device):
    load_rdar_fix(dev)
    if TweakID.DynamicIsland in tweaks:
        return
    additional_tweaks = get_mobilegestalt_tweaks()
    # add to tweaks
    tweaks.update(additional_tweaks)

def load_eligibility(dev: Device):
    if TweakID.AIGestalt in tweaks:
        return
    additional_tweaks = {
        TweakID.EUEnabler: EligibilityTweak(),
        TweakID.AIEligibility: AITweak(),
        TweakID.AIGestalt: MobileGestaltTweak("A62OafQ85EJAiiqKn4agtg"),
        TweakID.AIFeatureFlags: FeatureFlagTweak(flag_category="Siri", flag_names=['sae_override', 'assistant_engine_override']),
        TweakID.AIFeatureFlagsUI: FeatureFlagTweak(flag_category="SiriUI", flag_names=["sae"]),
        TweakID.SpoofModel: MobileGestaltPickerTweak("h9jDsbgj7xIVeIQ8S3/X3Q", values=[
            # Default
            "Placeholder", # 0 | Original

            # iPhone
            "iPhone16,1", # 1 | iPhone 15 Pro
            "iPhone16,2", # 2 | iPhone 15 Pro Max
            "iPhone17,3", # 3 | iPhone 16
            "iPhone17,4", # 4 | iPhone 16 Plus
            "iPhone17,1", # 5 | iPhone 16 Pro
            "iPhone17,2", # 6 | iPhone 16 Pro Max
            "iPhone18,3", # 7 | iPhone 17

            # A17 Pro iPads
            "iPad16,1", # 8 | iPad Mini (A17 Pro) (W)
            "iPad16,2", # 9 | iPad Mini (A17 Pro) (C)
        
            # M4 iPads
            "iPad16,5", # 10 | iPad Pro (13-inch) (M4) (W)
            "iPad16,6", # 11 | iPad Pro (13-inch) (M4) (C)
            "iPad16,3", # 12 | iPad Pro (11-inch) (M4) (W)
            "iPad16,4", # 13 | iPad Pro (11-inch) (M4) (C)

            # M2 iPads
            "iPad14,5", # 14 | iPad Pro (12.9-inch) (M2) (W)
            "iPad14,6", # 15 | iPad Pro (12.9-inch) (M2) (C)
            "iPad14,3", # 16 | iPad Pro (11-inch) (M2) (W)
            "iPad14,4", # 17 | iPad Pro (11-inch) (M2) (C)
            "iPad14,10", # 18 | iPad Air (13-inch) (M2) (W)
            "iPad14,11", # 19 | iPad Air (13-inch) (M2) (C)
            "iPad14,8", # 20 | iPad Air (11-inch) (M2) (W)
            "iPad14,9", # 21 | iPad Air (11-inch) (M2) (C)

            # M1 iPads
            "iPad13,4", # 22 | iPad Pro (11-inch) (M1) (W)
            "iPad13,5", # 23 | iPad Pro (11-inch) (M1) (C)
            "iPad13,8", # 24 | iPad Pro (12.9-inch) (M1) (W)
            "iPad13,9", # 25 | iPad Pro (12.9-inch) (M1) (C)
            "iPad13,16", # 26 | iPad Air (M1) (W)
            "iPad13,17", # 27 | iPad Air (M1) (C)
        ]),
        TweakID.SpoofHardware: MobileGestaltPickerTweak("oYicEKzVTz4/CxxE05pEgQ", values=[
            # Default
            "Placeholder", # 0 | Original

            # iPhone
            "D83AP", # 1 | iPhone 15 Pro
            "D84AP", # 2 | iPhone 15 Pro Max
            "D47AP", # 3 | iPhone 16
            "D48AP", # 4 | iPhone 16 Plus
            "D93AP", # 5 | iPhone 16 Pro
            "D94AP", # 6 | iPhone 16 Pro Max
            "V57AP", # 7 | iPhone 17

            # A17 Pro iPads
            "J410AP", # 8 | iPad Mini (A17 Pro) (W)
            "J411AP", # 9 | iPad Mini (A17 Pro) (C)
        
            # M4 iPads
            "J720AP", # 10 | iPad Pro (13-inch) (M4) (W)
            "J721AP", # 11 | iPad Pro (13-inch) (M4) (C)
            "J717AP", # 12 | iPad Pro (11-inch) (M4) (W)
            "J718AP", # 13 | iPad Pro (11-inch) (M4) (C)

            # M2 iPads
            "J620AP", # 14 | iPad Pro (12.9-inch) (M2) (W)
            "J621AP", # 15 | iPad Pro (12.9-inch) (M2) (C)
            "J617AP", # 16 | iPad Pro (11-inch) (M2) (W)
            "J618AP", # 17 | iPad Pro (11-inch) (M2) (C)
            "J537AP", # 18 | iPad Air (13-inch) (M2) (W)
            "J538AP", # 19 | iPad Air (13-inch) (M2) (C)
            "J507AP", # 20 | iPad Air (11-inch) (M2) (W)
            "J508AP", # 21 | iPad Air (11-inch) (M2) (C)

            # M1 iPads
            "J517AP", # 22 | iPad Pro (11-inch) (M1) (W)
            "J517xAP", # 23 | iPad Pro (11-inch) (M1) (C)
            "J522AP", # 24 | iPad Pro (12.9-inch) (M1) (W)
            "J522xAP", # 25 | iPad Pro (12.9-inch) (M1) (C)
            "J407AP", # 26 | iPad Air (M1) (W)
            "J408AP", # 27 | iPad Air (M1) (C)
        ]),
        TweakID.SpoofCPU: MobileGestaltPickerTweak("5pYKlGnYYBzGvAlIU8RjEQ", values=[
            # Default
            "Placeholder", # 0 | Original

            # iPhone
            "t8130", # 1 | iPhone 15 Pro
            "t8130", # 2 | iPhone 15 Pro Max
            "t8140", # 3 | iPhone 16
            "t8140", # 4 | iPhone 16 Plus
            "t8140", # 5 | iPhone 16 Pro
            "t8140", # 6 | iPhone 16 Pro Max
            "t8150", # 7 | iPhone 17

            # A17 Pro iPads
            "t8130", # 8 | iPad Mini (A17 Pro) (W)
            "t8130", # 9 | iPad Mini (A17 Pro) (C)
        
            # M4 iPads
            "t8182", # 10 | iPad Pro (13-inch) (M4) (W)
            "t8182", # 11 | iPad Pro (13-inch) (M4) (C)
            "t8182", # 12 | iPad Pro (11-inch) (M4) (W)
            "t8182", # 13 | iPad Pro (11-inch) (M4) (C)

            # M2 iPads
            "t8112", # 14 | iPad Pro (12.9-inch) (M2) (W)
            "t8112", # 15 | iPad Pro (12.9-inch) (M2) (C)
            "t8112", # 16 | iPad Pro (11-inch) (M2) (W)
            "t8112", # 17 | iPad Pro (11-inch) (M2) (C)
            "t8112", # 18 | iPad Air (13-inch) (M2) (W)
            "t8112", # 19 | iPad Air (13-inch) (M2) (C)
            "t8112", # 20 | iPad Air (11-inch) (M2) (W)
            "t8112", # 21 | iPad Air (11-inch) (M2) (C)

            # M1 iPads
            "t8103", # 22 | iPad Pro (11-inch) (M1) (W)
            "t8103", # 23 | iPad Pro (11-inch) (M1) (C)
            "t8103", # 24 | iPad Pro (12.9-inch) (M1) (W)
            "t8103", # 25 | iPad Pro (12.9-inch) (M1) (C)
            "t8103", # 26 | iPad Air (M1) (W)
            "t8103", # 27 | iPad Air (M1) (C)
        ])
    }
    # load settings
    if dev != None:
        additional_tweaks[TweakID.SpoofModel].value[0] = dev.model
        additional_tweaks[TweakID.SpoofHardware].value[0] = dev.hardware
        additional_tweaks[TweakID.SpoofCPU].value[0] = dev.cpu
    # add to tweaks
    tweaks.update(additional_tweaks)

def load_featureflags():
    if TweakID.ClockAnim in tweaks:
        return
    additional_tweaks = {
        TweakID.ClockAnim: FeatureFlagTweak(flag_category='SpringBoard',
                     flag_names=['SwiftUITimeAnimation']),
        TweakID.Lockscreen: FeatureFlagTweak(flag_category="SpringBoard",
                        flag_names=['AutobahnQuickSwitchTransition', 'SlipSwitch', 'PosterEditorKashida']),
        TweakID.PhotoUI: FeatureFlagTweak(flag_category='Photos', flag_names=['Lemonade'], is_list=False, inverted=True),
        TweakID.AI: FeatureFlagTweak(flag_category='SpringBoard', flag_names=['Domino', 'SuperDomino']),
        TweakID.KioskMode: FeatureFlagTweak(flag_category='PreferencesFramework', flag_names=['ForcedRetailKioskMode']),

        TweakID.SolariumFFSwiftUI: FeatureFlagTweak(flag_category='SwiftUI', flag_names=['Solarium'], inverted=True),
        TweakID.SolariumFFSpringBoard: FeatureFlagTweak(flag_category='SpringBoard', flag_names=['SolariumElasticHUD'], inverted=True),

        TweakID.SolariumFFIconServices: FeatureFlagTweak(flag_category='IconServices', flag_names=['EnhancedGlass', 'SolariumCornerRadius'], inverted=True),

        TweakID.SolariumFFDocumentCamera: FeatureFlagTweak(flag_category='DocumentCamera', flag_names=['CaptureLiquidGlass'], inverted=True),
        TweakID.SolariumFFPhotos: FeatureFlagTweak(flag_category='Photos', flag_names=['SolariumGridMagicPocket'], inverted=True),
        TweakID.SolariumFFAppleMediaServices: FeatureFlagTweak(flag_category='AppleMediaServices', flag_names=['Solarium'], inverted=True),

        TweakID.SolariumFFSharing: FeatureFlagTweak(flag_category='Sharing', flag_names=['ShareSheetSolarium'], inverted=True),
        TweakID.SolariumFFMail: FeatureFlagTweak(flag_category='Mail', flag_names=['SolariumSearch'], inverted=True)
    }
    tweaks.update(additional_tweaks)

def load_springboard():
    if TweakID.LockScreenFootnote in tweaks:
        return
    additional_tweaks = {
        TweakID.LockScreenFootnote: BasicPlistTweak(
            FileLocation.footnote,
            key="LockScreenFootnote", value=""
        ),
        TweakID.WatchOSCompatibility: AdvancedPlistTweak(
            file_location=FileLocation.nanoregistry,
            keyValues={
                "IOS_PAIRING_EOL_MIN_PAIRING_COMPATIBILITY_VERSION_CHIPIDS": "",
                "maxPairingCompatibilityVersion": 37,
                "lastRestoreIdentifier": "CD97EEB8-BCD2-486B-BC13-C384E6B916C4", # not sure if this is needed
                "minPairingCompatibilityVersionWithChipID": 1,
                "lastRestoreIdentifier_state": 0,
                "AdvertisingIdentifierSeed": "85E70251-1960-4DA0-A321-B68AC118FAB5", # this prolly isn't needed either
                "minPairingCompatibilityVersion": 1
            }
        ),
        TweakID.AirDropDisableTimeLimit: BasicPlistTweak(
            FileLocation.airdrop,
            "OverrideTimeLimitEveryoneMode"
        ),
        TweakID.SBDontLockAfterCrash: BasicPlistTweak(
            FileLocation.springboard,
            "SBDontLockAfterCrash"
        ),
        TweakID.SBDontDimOrLockOnAC: BasicPlistTweak(
            FileLocation.springboard,
            "SBDontDimOrLockOnAC"
        ),
        TweakID.SBHideLowPowerAlerts: BasicPlistTweak(
            FileLocation.springboard,
            "SBHideLowPowerAlerts"
        ),
        TweakID.SBHideACPower: BasicPlistTweak(
            FileLocation.springboard,
            "SBHideACPower"
        ),
        TweakID.SBNeverBreadcrumb: BasicPlistTweak(
            FileLocation.springboard,
            "SBNeverBreadcrumb"
        ),
        TweakID.SBShowSupervisionTextOnLockScreen: BasicPlistTweak(
            FileLocation.springboard,
            "SBShowSupervisionTextOnLockScreen"
        ),
        TweakID.AirplaySupport: BasicPlistTweak(
            FileLocation.springboard,
            "SBExtendedDisplayOverrideSupportForAirPlayAndDontFileRadars"
        ),
        TweakID.SBMinimumLockscreenIdleTime: BasicPlistTweak(
            FileLocation.springboard,
            key="SBMinimumLockscreenIdleTime",
            value=5
        ),
        TweakID.SBAlwaysShowSystemApertureInSnapshots: BasicPlistTweak(
            FileLocation.springboard,
            "SBAlwaysShowSystemApertureInSnapshots"
        ),
        TweakID.HideDICompletely: BasicPlistTweak(
            FileLocation.springboard,
            "SBSuppressDynamicIslandCompletely"
        ),
        TweakID.SBShowAuthenticationEngineeringUI: BasicPlistTweak(
            FileLocation.springboard,
            "SBShowAuthenticationEngineeringUI"
        ),
        TweakID.UseFloatingTabBar: BasicPlistTweak(
            FileLocation.uikit,
            key="UseFloatingTabBar",
            value=False
        )
    }
    tweaks.update(additional_tweaks)

def load_internal():
    if TweakID.RTL in tweaks:
        return
    additional_tweaks = {
        TweakID.SBBuildNumber: BasicPlistTweak(
            FileLocation.globalPreferences,
            "UIStatusBarShowBuildVersion"
        ),
        TweakID.RTL: BasicPlistTweak(
            FileLocation.globalPreferences,
            "NSForceRightToLeftWritingDirection"
        ),
        TweakID.LTR: BasicPlistTweak(
            FileLocation.globalPreferences,
            "NSForceLeftToRightWritingDirection"
        ),
        TweakID.SBIconVisibility: BasicPlistTweak(
            FileLocation.globalPreferences,
            "SBIconVisibility"
        ),
        TweakID.MetalForceHudEnabled: BasicPlistTweak(
            FileLocation.globalPreferences,
            "MetalForceHudEnabled"
        ),
        TweakID.iMessageDiagnosticsEnabled: BasicPlistTweak(
            FileLocation.globalPreferences,
            "iMessageDiagnosticsEnabled"
        ),
        TweakID.IDSDiagnosticsEnabled: BasicPlistTweak(
            FileLocation.globalPreferences,
            "IDSDiagnosticsEnabled"
        ),
        TweakID.VCDiagnosticsEnabled: BasicPlistTweak(
            FileLocation.globalPreferences,
            "VCDiagnosticsEnabled"
        ),
        TweakID.AccessoryDeveloperEnabled: BasicPlistTweak(
            FileLocation.globalPreferences,
            "AccessoryDeveloperEnabled"
        ),
        TweakID.KeyFlick: BasicPlistTweak(
            FileLocation.globalPreferences,
            "GesturesEnabled"
        ),
        TweakID.DisableSecondsHand: BasicPlistTweak(
            FileLocation.globalPreferences,
            "SBDisableClockIconSecondsHand"
        ),
        TweakID.DisableSearchingWebsites: BasicPlistTweak(
            FileLocation.globalPreferences,
            "SBSearchDisabledDomains"
        ),
        TweakID.ShowButtonHints: BasicPlistTweak(
            FileLocation.globalPreferences,
            "SBHardwareButtonHintDropletsAlwaysVisibleInSnapshots"
        ),
        TweakID.AppStoreDebug: BasicPlistTweak(
            FileLocation.appStore,
            "debugGestureEnabled"
        ),
        TweakID.NotesDebugMode: BasicPlistTweak(
            FileLocation.notes,
            "DebugModeEnabled"
        ),
        TweakID.BKDigitizerVisualizeTouches: BasicPlistTweak(
            FileLocation.backboardd,
            "BKDigitizerVisualizeTouches"
        ),
        TweakID.BKHideAppleLogoOnLaunch: BasicPlistTweak(
            FileLocation.backboardd,
            "BKHideAppleLogoOnLaunch"
        ),
        TweakID.EnableWakeGestureHaptic: BasicPlistTweak(
            FileLocation.coreMotion,
            "EnableWakeGestureHaptic"
        ),
        TweakID.PlaySoundOnPaste: BasicPlistTweak(
            FileLocation.pasteboard,
            "PlaySoundOnPaste"
        ),
        TweakID.AnnounceAllPastes: BasicPlistTweak(
            FileLocation.pasteboard,
            "AnnounceAllPastes"
        )
    }
    tweaks.update(additional_tweaks)

def load_liquidglass():
    if TweakID.DisableSolarium in tweaks:
        return
    additional_tweaks = {
        TweakID.ForceSolariumFallback: BasicPlistTweak(
            FileLocation.globalPreferences,
            "SolariumForceFallback"
        ),
        TweakID.DisableSolarium: BasicPlistTweak(
            FileLocation.globalPreferences,
            "com.apple.SwiftUI.DisableSolarium"
        ),
        TweakID.IgnoreSolariumLinkedOnCheck: BasicPlistTweak(
            FileLocation.globalPreferences,
            "com.apple.SwiftUI.IgnoreSolariumLinkedOnCheck"
        ),
        TweakID.NoLiquidClock: BasicPlistTweak(
            FileLocation.globalPreferences,
            "SBDisallowGlassTime"
        ),
        TweakID.NoLiquidDock: BasicPlistTweak(
            FileLocation.globalPreferences,
            "SBDisableGlassDock"
        ),
        TweakID.DisableSpecularMotion: BasicPlistTweak(
            FileLocation.globalPreferences,
            "SBDisableSpecularEverywhereUsingLSSAssertion"
        ),
        TweakID.DisableOuterRefraction: BasicPlistTweak(
            FileLocation.globalPreferences,
            "SolariumDisableOuterRefraction"
        ),
        TweakID.DisableSolariumHDR: BasicPlistTweak(
            FileLocation.globalPreferences,
            "SolariumAllowHDR",
            value=False
        )
    }
    tweaks.update(additional_tweaks)

def load_risky():
    if TweakID.CustomResolution in tweaks:
        return
    additional_tweaks = {
        TweakID.DisableOTAFile: AdvancedPlistTweak(
            FileLocation.ota,
            {
                "MobileAssetServerURL-com.apple.MobileAsset.MobileSoftwareUpdate.UpdateBrain": "https://mesu.apple.com/assets/tvOS16DeveloperSeed",
                "MobileAssetSUAllowOSVersionChange": False,
                "MobileAssetSUAllowSameVersionFullReplacement": False,
                "MobileAssetServerURL-com.apple.MobileAsset.RecoveryOSUpdate": "https://mesu.apple.com/assets/tvOS16DeveloperSeed",
                "MobileAssetServerURL-com.apple.MobileAsset.RecoveryOSUpdateBrain": "https://mesu.apple.com/assets/tvOS16DeveloperSeed",
                "MobileAssetServerURL-com.apple.MobileAsset.SoftwareUpdate": "https://mesu.apple.com/assets/tvOS16DeveloperSeed",
                "MobileAssetAssetAudience": "65254ac3-f331-4c19-8559-cbe22f5bc1a6"
            }, is_risky=True
        ),
        TweakID.CustomResolution: AdvancedPlistTweak(
            FileLocation.resolution,
            {}, # empty as to not cause issues when only 1 value is inputted
            is_risky=True
        )
    }
    tweaks.update(additional_tweaks)

def load_daemons():
    if TweakID.Daemons in tweaks:
        return
    additional_tweaks = {
        TweakID.Daemons: AdvancedPlistTweak(
            FileLocation.disabledDaemons,
            {
                "com.apple.magicswitchd.companion": True,
                "com.apple.security.otpaird": True,
                "com.apple.dhcp6d": True,
                "com.apple.bootpd": True,
                "com.apple.ftp-proxy-embedded": False,
                "com.apple.relevanced": True
            },
            owner=0, group=0
        ),
        TweakID.ClearScreenTimeAgentPlist: NullifyFileTweak(FileLocation.screentime),
    }
    tweaks.update(additional_tweaks)

# Tracks every TweakID loaded by the iOS 27 / LG+Siri+A11y page so the
# "Enable All" button knows what to enable without hard-coding the list twice.
_page_tweak_ids: set = set()


def load_ios27():
    if TweakID.SolariumFFMessages in tweaks:
        return
    S  = FileLocation.springboard
    GP = FileLocation.globalPreferences
    SI = FileLocation.siri
    additional_tweaks = {
        # ── Siri – real Apple MDM keys (com.apple.siri.plist) ────────────────
        TweakID.Siri2FloatingBubble:    BasicPlistTweak(SI, 'AssistantEnabled'),
        TweakID.Siri2AmbientMode:       BasicPlistTweak(SI, 'VoiceTriggerEnabled'),
        TweakID.Siri2VisualResponse:    BasicPlistTweak(SI, 'UIAssistantEnabled'),
        TweakID.Siri2NaturalVoice:      BasicPlistTweak(SI, 'KeyboardEnabled'),
        TweakID.Siri2OnScreenContext:   BasicPlistTweak(SI, 'SiriProfanityFilter', value=False),
        TweakID.Siri2CallScreening:     BasicPlistTweak(SI, 'AssistantAllowedForAnyLockscreen'),

        # ── Liquid Glass per-app extensions (FeatureFlagTweak → Global.plist) ─
        TweakID.SolariumFFMessages:     FeatureFlagTweak('Messages',          ['Solarium']),
        TweakID.SolariumFFMaps:         FeatureFlagTweak('Maps',              ['Solarium']),
        TweakID.SolariumFFSafari:       FeatureFlagTweak('MobileSafari',      ['Solarium']),
        TweakID.SolariumFFSpotlight:    FeatureFlagTweak('Spotlight',         ['Solarium']),
        TweakID.SolariumFFControlCenter:FeatureFlagTweak('ControlCenter',     ['Solarium']),
        TweakID.SolariumFFNotifications:FeatureFlagTweak('UserNotificationsUI',['Solarium']),
        TweakID.SolariumFFWidgets:      FeatureFlagTweak('WidgetKit',         ['Solarium']),
        TweakID.SolariumFFMusic:        FeatureFlagTweak('Music',             ['Solarium']),
        TweakID.SolariumFFPodcasts:     FeatureFlagTweak('Podcasts',          ['Solarium']),
        TweakID.SolariumFFPhone:        FeatureFlagTweak('Phone',             ['Solarium']),
        TweakID.SolariumFFCalendar:     FeatureFlagTweak('Calendar',          ['Solarium']),
        TweakID.SolariumFFReminders:    FeatureFlagTweak('Reminders',         ['Solarium']),
        TweakID.SolariumFFNotes:        FeatureFlagTweak('Notes',             ['Solarium']),

        # ── Liquid Glass fine-tuning (GlobalPreferences) ──────────────────────
        TweakID.NoLiquidStatusBar:      BasicPlistTweak(GP, 'SBDisableGlassStatusBar'),
        TweakID.NoLiquidNotifications:  BasicPlistTweak(GP, 'SBDisableGlassNotifications'),
        TweakID.SolariumHighContrast:   BasicPlistTweak(GP, 'SolariumHighContrast'),
        TweakID.SolariumForceLightTint: BasicPlistTweak(GP, 'SolariumForceLightTint'),
        TweakID.SolariumMaxBlur:        BasicPlistTweak(GP, 'SolariumMaxBlur'),

        # ── SpringBoard (com.apple.springboard.plist managed preferences) ─────
        TweakID.SBShowBatteryPercentageAlways: BasicPlistTweak(S, 'SBUIForceDisplayBatteryPercentageNew'),
        TweakID.SBHideHomeIndicator:           BasicPlistTweak(S, 'SBHideHomeIndicator'),
        TweakID.SBDisableParallaxEffect:       BasicPlistTweak(S, 'SBDisableParallax'),
        TweakID.SBAlwaysGlassHeaders:          BasicPlistTweak(S, 'SBAlwaysShowGlassGroupHeaders'),
        TweakID.SBExpandedDynamicIsland:       BasicPlistTweak(S, 'SBEnableExpandedDynamicIslandPersistent'),
        TweakID.SBAlwaysShowClockDI:           BasicPlistTweak(S, 'SBShowClockWithDynamicIsland'),

        # ── Audio Processing (FeatureFlagTweak → Global.plist) ────────────────
        TweakID.AudioSpatialDefault:    FeatureFlagTweak('CoreAudio',      ['SpatialAudioProcessing']),
        TweakID.AudioEnhancedSpeaker:   FeatureFlagTweak('AVFoundation',   ['EnhancedSpeakerOutput']),
        TweakID.AudioPersonalizedSpatial: FeatureFlagTweak('AVFoundation', ['PersonalizedSpatialAudio']),
        TweakID.AudioBackgroundSounds:  FeatureFlagTweak('Accessibility',  ['BackgroundSounds']),
        TweakID.AudioHeadphoneAccom:    FeatureFlagTweak('Accessibility',  ['HeadphoneAccommodations']),
        TweakID.AudioLoudnessNorm:      FeatureFlagTweak('AVFoundation',   ['LoudnessNormalization']),
        TweakID.AudioSoundEffectsEnabled: BasicPlistTweak(GP, 'SBSoundEffectsEnabled'),
        TweakID.AudioHapticsSync:       BasicPlistTweak(GP, 'SBAudioHapticsSyncEnabled'),
    }
    tweaks.update(additional_tweaks)
    _page_tweak_ids.update(additional_tweaks.keys())


def load_maxos_ui():
    """SpringBoard & UIKit feature flags — maxregnerOS UI layer."""
    if TweakID.SBFFFloatingDock in tweaks:
        return
    additional_tweaks = {
        # SpringBoard UI feature flags
        TweakID.SBFFFloatingDock:             FeatureFlagTweak('SpringBoard', ['FloatingDock']),
        TweakID.SBFFDenseHomeScreen:          FeatureFlagTweak('SpringBoard', ['DenseHomeScreen']),
        TweakID.SBFFAppSwitcherV2:            FeatureFlagTweak('SpringBoard', ['EnhancedAppSwitcher']),
        TweakID.SBFFGlassFolders:             FeatureFlagTweak('SpringBoard', ['LiquidGlassFolders']),
        TweakID.SBFFLiveActivitiesPersistent: FeatureFlagTweak('SpringBoard', ['PersistentLiveActivities']),
        TweakID.SBFFAdaptiveGrid:             FeatureFlagTweak('SpringBoard', ['HomeScreenAdaptiveGrid']),
        TweakID.SBFFContextWidgets:           FeatureFlagTweak('SpringBoard', ['ContextualWidgets']),
        TweakID.SBFFProximityAnimations:      FeatureFlagTweak('SpringBoard', ['ProximityBasedAnimations']),
        TweakID.SBFFLargeWidgetGrid:          FeatureFlagTweak('SpringBoard', ['LargeWidgetGridSize']),
        TweakID.SBFFDynamicBackground:        FeatureFlagTweak('SpringBoard', ['DynamicBackgroundAdaptation']),
        TweakID.SBFFGlassIconShimmer:         FeatureFlagTweak('SpringBoard', ['GlassIconShimmer']),
        TweakID.SBFFPageIndicatorRedesign:    FeatureFlagTweak('SpringBoard', ['PageIndicatorRedesign']),
        TweakID.SBFFEnhancedAppLibrary:       FeatureFlagTweak('SpringBoard', ['EnhancedAppLibrarySearch']),
        TweakID.SBFFGlassSectionDividers:     FeatureFlagTweak('SpringBoard', ['GlassSectionDividers']),
        TweakID.SBFFDebugUIOverlay:           FeatureFlagTweak('SpringBoard', ['UIDebugOverlay']),
        # UIKit feature flags
        TweakID.UIKitFFGlassSheets:           FeatureFlagTweak('UIKit', ['GlassBottomSheets']),
        TweakID.UIKitFFPillButtons:           FeatureFlagTweak('UIKit', ['PillShapedButtons']),
        TweakID.UIKitFFLargeNavHeaders:       FeatureFlagTweak('UIKit', ['LargeNavigationHeaders']),
        TweakID.UIKitFFSwipeBackV2:           FeatureFlagTweak('UIKit', ['SwipeBackGestureV2']),
        TweakID.UIKitFFFloatingMenus:         FeatureFlagTweak('UIKit', ['FloatingMenuPresentations']),
        TweakID.UIKitFFCardLayouts:           FeatureFlagTweak('UIKit', ['AdaptiveCardLayouts']),
        TweakID.UIKitFFRubberBandPhysics:     FeatureFlagTweak('UIKit', ['RubberBandScrollPhysics']),
        TweakID.UIKitFFGlassAlerts:           FeatureFlagTweak('UIKit', ['GlassAlertViews']),
        TweakID.UIKitFFCompactProgress:       FeatureFlagTweak('UIKit', ['CompactProgressIndicators']),
        TweakID.UIKitFFHapticKeyboard:        FeatureFlagTweak('UIKit', ['HapticKeyboardFeedback']),
        TweakID.UIKitFFEnhancedTextRendering: FeatureFlagTweak('UIKit', ['EnhancedTextRendering']),
        TweakID.UIKitFFDynamicColorAdaptation:FeatureFlagTweak('UIKit', ['DynamicColorAdaptation']),
    }
    tweaks.update(additional_tweaks)
    _page_tweak_ids.update(additional_tweaks.keys())


def load_maxos_apps():
    """Per-app feature flags: Photos, Camera, Messages, FaceTime, Maps, Safari."""
    if TweakID.PhotosFFEnhancedEditing in tweaks:
        return
    additional_tweaks = {
        # Photos
        TweakID.PhotosFFEnhancedEditing:    FeatureFlagTweak('Photos',    ['EnhancedEditing']),
        TweakID.PhotosFFAIAlbums:           FeatureFlagTweak('Photos',    ['AISmartAlbums']),
        TweakID.PhotosFFMemoriesV2:         FeatureFlagTweak('Photos',    ['MemoriesV2']),
        TweakID.PhotosFFImprovedSearch:     FeatureFlagTweak('Photos',    ['ImprovedSearch']),
        # Camera
        TweakID.CameraFFProResVideo:        FeatureFlagTweak('Camera',    ['ProResVideoEnabled']),
        TweakID.CameraFFMacroPro:           FeatureFlagTweak('Camera',    ['MacroPro']),
        TweakID.CameraFFNightModePortrait:  FeatureFlagTweak('Camera',    ['NightModePortrait']),
        TweakID.CameraFFProRAWMax:          FeatureFlagTweak('Camera',    ['ProRAWMax']),
        TweakID.CameraFFCinematicV2:        FeatureFlagTweak('Camera',    ['CinematicModeV2']),
        TweakID.CameraFFQuantumHDR:         FeatureFlagTweak('Camera',    ['QuantumHDR']),
        # Messages
        TweakID.MsgFFEnhancedSearch:        FeatureFlagTweak('Messages',  ['EnhancedSearch']),
        TweakID.MsgFFEffectsV2:             FeatureFlagTweak('Messages',  ['EffectsV2']),
        TweakID.MsgFFCollaborativeSharing:  FeatureFlagTweak('Messages',  ['CollaborativeSharing']),
        TweakID.MsgFFRichLinksV2:           FeatureFlagTweak('Messages',  ['RichLinksV2']),
        # FaceTime
        TweakID.FaceTimeFFPersonSegmentation: FeatureFlagTweak('FaceTime',['PersonSegmentation']),
        TweakID.FaceTimeFFReactionAnimations: FeatureFlagTweak('FaceTime',['ReactionAnimations']),
        TweakID.FaceTimeFFSharedPlaybackV2: FeatureFlagTweak('FaceTime',  ['SharedPlaybackV2']),
        TweakID.FaceTimeFFSpatialAudioCall: FeatureFlagTweak('FaceTime',  ['SpatialAudioCall']),
        # Maps
        TweakID.MapsFFImmersiveView:        FeatureFlagTweak('Maps',      ['ImmersiveView']),
        TweakID.MapsFFARWalkDirections:     FeatureFlagTweak('Maps',      ['ARWalkDirections']),
        TweakID.MapsFFOfflineEnhanced:      FeatureFlagTweak('Maps',      ['OfflineMapsEnhanced']),
        TweakID.MapsFFRealtimeTrafficV2:    FeatureFlagTweak('Maps',      ['RealtimeTrafficV2']),
        TweakID.MapsFF3DPlaceCards:         FeatureFlagTweak('Maps',      ['PlaceCards3D']),
        TweakID.MapsFFElevationData:        FeatureFlagTweak('Maps',      ['ElevationData']),
        # Safari
        TweakID.SafariFFEnhancedPrivacy:    FeatureFlagTweak('MobileSafari', ['EnhancedPrivacyMode']),
        TweakID.SafariFFTabGroupsV2:        FeatureFlagTweak('MobileSafari', ['TabGroupsV2']),
        TweakID.SafariFFWebExtensionsAPI:   FeatureFlagTweak('MobileSafari', ['WebExtensionsAPI']),
        TweakID.SafariFFStartPageRedesign:  FeatureFlagTweak('MobileSafari', ['StartPageRedesign']),
        TweakID.SafariFFFloatingAddressBar: FeatureFlagTweak('MobileSafari', ['FloatingAddressBar']),
        TweakID.SafariFFReaderModeV2:       FeatureFlagTweak('MobileSafari', ['ReaderModeV2']),
    }
    tweaks.update(additional_tweaks)
    _page_tweak_ids.update(additional_tweaks.keys())


def load_maxos_system():
    """Widgets, Live Activities, Lock Screen, Notifications, Performance flags."""
    if TweakID.WidgetFFInteractiveWidgets in tweaks:
        return
    additional_tweaks = {
        # Widgets & Live Activities
        TweakID.WidgetFFInteractiveWidgets: FeatureFlagTweak('WidgetKit',       ['InteractiveWidgets']),
        TweakID.WidgetFFLargeFormat:        FeatureFlagTweak('WidgetKit',       ['LargeWidgetFormat']),
        TweakID.WidgetFFAnimatedWidgets:    FeatureFlagTweak('WidgetKit',       ['AnimatedWidgets']),
        TweakID.LiveActFFPersistentMode:    FeatureFlagTweak('LiveActivities',  ['PersistentMode']),
        TweakID.LiveActFFGlassPresentation: FeatureFlagTweak('LiveActivities',  ['GlassPresentation']),
        TweakID.LiveActFFStandbyV2:         FeatureFlagTweak('LiveActivities',  ['StandbyModeV2']),
        # Lock Screen
        TweakID.LockFFWidgetsV2:            FeatureFlagTweak('SpringBoard',     ['LockScreenWidgetsV2']),
        TweakID.LockFFDepthEffectClock:     FeatureFlagTweak('SpringBoard',     ['DepthEffectClock']),
        TweakID.LockFFLiveWeatherBG:        FeatureFlagTweak('SpringBoard',     ['LiveWeatherBackground']),
        TweakID.LockFFAlwaysOnDisplayV2:    FeatureFlagTweak('SpringBoard',     ['AlwaysOnDisplayV2']),
        # Notifications
        TweakID.NotifFFStackedBanners:      FeatureFlagTweak('UserNotificationsUI', ['StackedBanners']),
        TweakID.NotifFFGlassNotifications:  FeatureFlagTweak('UserNotificationsUI', ['GlassNotifications']),
        TweakID.NotifFFQuickRepliesV2:      FeatureFlagTweak('UserNotificationsUI', ['QuickRepliesV2']),
        TweakID.NotifFFSummaryV2:           FeatureFlagTweak('UserNotificationsUI', ['NotificationSummaryV2']),
        # Performance
        TweakID.PerfFFEnhancedLowPower:     FeatureFlagTweak('SpringBoard',     ['EnhancedLowPowerMode']),
        TweakID.PerfFFBackgroundRefreshV2:  FeatureFlagTweak('SpringBoard',     ['BackgroundRefreshV2']),
        TweakID.PerfFFLowLatencyAudio:      FeatureFlagTweak('CoreAudio',       ['LowLatencyProcessing']),
        TweakID.PerfFFHardwareAcceleration: FeatureFlagTweak('AVFoundation',    ['HardwareAcceleration']),
        TweakID.PerfFFThermalStatusUI:      FeatureFlagTweak('SpringBoard',     ['ThermalStatusUI']),
        TweakID.PerfFFMemoryPressureMonitor:FeatureFlagTweak('SpringBoard',     ['MemoryPressureMonitor']),
        TweakID.PerfFFProcessPriorityBoost: FeatureFlagTweak('SpringBoard',     ['ProcessPriorityBoost']),
        TweakID.PerfFFUltraLowLatencyInput: FeatureFlagTweak('SpringBoard',     ['UltraLowLatencyInput']),
    }
    tweaks.update(additional_tweaks)
    _page_tweak_ids.update(additional_tweaks.keys())


def load_maxos_exclusive():
    """maxregnerOS signature feature flags."""
    if TweakID.MaxOSGlassEverywhere in tweaks:
        return
    additional_tweaks = {
        TweakID.MaxOSGlassEverywhere:      FeatureFlagTweak('SpringBoard',   ['GlassEverywhere']),
        TweakID.MaxOSFluidMotionEngine:    FeatureFlagTweak('UIKit',         ['FluidMotionEngine']),
        TweakID.MaxOSNeuralEngineBoost:    FeatureFlagTweak('CoreML',        ['EnhancedNeuralEngine']),
        TweakID.MaxOSProDisplayRendering:  FeatureFlagTweak('CoreGraphics',  ['ProDisplayRendering']),
        TweakID.MaxOSHyperSmoothScrolling: FeatureFlagTweak('UIKit',         ['HyperSmoothScrolling']),
        TweakID.MaxOSChromaticAberration:  FeatureFlagTweak('CoreImage',     ['ChromaticAberrationEffect']),
        TweakID.MaxOSDepthSensingV2:       FeatureFlagTweak('ARKit',         ['DepthSensingV2']),
        TweakID.MaxOSAmbientIntelligence:  FeatureFlagTweak('Siri',          ['AmbientIntelligence']),
        TweakID.MaxOSProHapticsEngine:     FeatureFlagTweak('CoreHaptics',   ['ProHapticsEngine']),
        TweakID.MaxOSDynamicIslandPro:     FeatureFlagTweak('SpringBoard',   ['DynamicIslandPro']),
    }
    tweaks.update(additional_tweaks)
    _page_tweak_ids.update(additional_tweaks.keys())


# maxregnerOS Mode: curated set of the highest-impact tweaks for maximum visual effect
MAXREGNEROS_MODE_IDS = frozenset([
    TweakID.SolariumFFMessages, TweakID.SolariumFFMaps, TweakID.SolariumFFSafari,
    TweakID.SolariumFFControlCenter, TweakID.SolariumFFNotifications, TweakID.SolariumFFWidgets,
    TweakID.SolariumFFMusic, TweakID.SolariumFFPhone, TweakID.SolariumFFCalendar,
    TweakID.SolariumFFNotes, TweakID.SolariumFFSpotlight,
    TweakID.SBShowBatteryPercentageAlways, TweakID.SBAlwaysGlassHeaders,
    TweakID.SBExpandedDynamicIsland, TweakID.SBAlwaysShowClockDI,
    TweakID.SBFFGlassFolders, TweakID.SBFFAppSwitcherV2, TweakID.SBFFLiveActivitiesPersistent,
    TweakID.SBFFAdaptiveGrid, TweakID.SBFFGlassIconShimmer, TweakID.SBFFDynamicBackground,
    TweakID.UIKitFFGlassSheets, TweakID.UIKitFFPillButtons, TweakID.UIKitFFGlassAlerts,
    TweakID.UIKitFFRubberBandPhysics, TweakID.UIKitFFCardLayouts,
    TweakID.LockFFDepthEffectClock, TweakID.LockFFLiveWeatherBG, TweakID.LockFFAlwaysOnDisplayV2,
    TweakID.LockFFWidgetsV2,
    TweakID.NotifFFGlassNotifications, TweakID.NotifFFStackedBanners,
    TweakID.WidgetFFInteractiveWidgets, TweakID.WidgetFFAnimatedWidgets,
    TweakID.LiveActFFGlassPresentation, TweakID.LiveActFFPersistentMode,
    TweakID.AudioSpatialDefault, TweakID.AudioPersonalizedSpatial, TweakID.AudioEnhancedSpeaker,
    TweakID.MaxOSGlassEverywhere, TweakID.MaxOSFluidMotionEngine,
    TweakID.MaxOSHyperSmoothScrolling, TweakID.MaxOSProDisplayRendering,
    TweakID.MaxOSProHapticsEngine, TweakID.MaxOSDynamicIslandPro,
    TweakID.SolariumHighContrast, TweakID.SolariumMaxBlur,
])


def load_all_tweaks(version: str):
    parsed_ver = Version(version)
    if parsed_ver <= Version("18.2"):
        # load mobilegestalt + eligibility tweaks
        load_mobilegestalt()
        load_eligibility()
    if parsed_ver < Version("18.1"):
        # load feature flags
        load_featureflags()
    load_springboard()
    load_internal()
    load_daemons()
    load_risky()
