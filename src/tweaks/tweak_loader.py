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

        # ── Audio (real GlobalPreferences managed-preference keys) ───────────
        TweakID.AudioSoundEffectsEnabled: BasicPlistTweak(GP, 'SBSoundEffectsEnabled'),
        TweakID.AudioHapticsSync:         BasicPlistTweak(GP, 'SBAudioHapticsSyncEnabled'),
    }
    tweaks.update(additional_tweaks)
    for tweak in additional_tweaks.values():
        tweak.set_enabled(True)
    _page_tweak_ids.update(additional_tweaks.keys())


def load_mros_solarium_extra():
    """Extended Liquid Glass per-app flags — all remaining Apple apps."""
    if TweakID.SolariumFFBooks in tweaks:
        return
    additional_tweaks = {
        TweakID.SolariumFFBooks:      FeatureFlagTweak('Books',       ['Solarium']),
        TweakID.SolariumFFWeather:    FeatureFlagTweak('Weather',     ['Solarium']),
        TweakID.SolariumFFStocks:     FeatureFlagTweak('Stocks',      ['Solarium']),
        TweakID.SolariumFFClock:      FeatureFlagTweak('Clock',       ['Solarium']),
        TweakID.SolariumFFCalculator: FeatureFlagTweak('Calculator',  ['Solarium']),
        TweakID.SolariumFFCamera:     FeatureFlagTweak('Camera',      ['Solarium']),
        TweakID.SolariumFFFaceTime:   FeatureFlagTweak('FaceTime',    ['Solarium']),
        TweakID.SolariumFFHealth:     FeatureFlagTweak('Health',      ['Solarium']),
        TweakID.SolariumFFWallet:     FeatureFlagTweak('Wallet',      ['Solarium']),
        TweakID.SolariumFFSettings:   FeatureFlagTweak('Preferences', ['Solarium']),
        TweakID.SolariumFFFiles:      FeatureFlagTweak('Files',       ['Solarium']),
        TweakID.SolariumFFTranslate:  FeatureFlagTweak('Translate',   ['Solarium']),
        TweakID.SolariumFFFreeform:   FeatureFlagTweak('Freeform',    ['Solarium']),
        TweakID.SolariumFFNews:       FeatureFlagTweak('News',        ['Solarium']),
        TweakID.SolariumFFContacts:   FeatureFlagTweak('Contacts',    ['Solarium']),
        TweakID.SolariumFFFindMy:     FeatureFlagTweak('FindMy',      ['Solarium']),
        TweakID.SolariumFFTV:         FeatureFlagTweak('TV',          ['Solarium']),
        TweakID.SolariumFFVoiceMemos: FeatureFlagTweak('VoiceMemos',  ['Solarium']),
        TweakID.SolariumFFShortcuts:  FeatureFlagTweak('Shortcuts',   ['Solarium']),
    }
    tweaks.update(additional_tweaks)
    for tweak in additional_tweaks.values():
        tweak.set_enabled(True)
    _page_tweak_ids.update(additional_tweaks.keys())


def load_mros_real_prefs():
    """Real system managed-preference overrides."""
    if TweakID.SysCoreProMotion in tweaks:
        return
    S  = FileLocation.springboard
    GP = FileLocation.globalPreferences
    additional_tweaks = {
        TweakID.SysCoreProMotion:   BasicPlistTweak(S,  'SBProMotionEnabled'),
        TweakID.SysCoreAnimSpeed:   BasicPlistTweak(GP, 'UIAnimationDragCoefficient', value=0.35),
        TweakID.SysCoreMTLOverlay:  BasicPlistTweak(GP, 'MTOverlayEnabled'),
        TweakID.SysCoreHideCarrier: BasicPlistTweak(S,  'SBHideCarrierText'),
        TweakID.SysCoreDevSettings: BasicPlistTweak(S,  'SBShowDeveloperSettings'),
        TweakID.SysCoreAlwaysAOD:   BasicPlistTweak(S,  'SBAlwaysOnDisplayEnabled'),
        TweakID.SysCoreAutoRotate:  BasicPlistTweak(S,  'SBDisableAutoRotation', value=False),
    }
    tweaks.update(additional_tweaks)
    for tweak in additional_tweaks.values():
        tweak.set_enabled(True)
    _page_tweak_ids.update(additional_tweaks.keys())


MAXREGNEROS_MODE_IDS = frozenset([
    # Liquid Glass — core apps
    TweakID.SolariumFFMessages, TweakID.SolariumFFMaps, TweakID.SolariumFFSafari,
    TweakID.SolariumFFControlCenter, TweakID.SolariumFFNotifications, TweakID.SolariumFFWidgets,
    TweakID.SolariumFFMusic, TweakID.SolariumFFPhone, TweakID.SolariumFFCalendar,
    TweakID.SolariumFFNotes, TweakID.SolariumFFSpotlight, TweakID.SolariumFFReminders,
    # Liquid Glass — extended apps
    TweakID.SolariumFFBooks, TweakID.SolariumFFWeather, TweakID.SolariumFFCamera,
    TweakID.SolariumFFFaceTime, TweakID.SolariumFFHealth, TweakID.SolariumFFWallet,
    TweakID.SolariumFFSettings, TweakID.SolariumFFFiles, TweakID.SolariumFFContacts,
    TweakID.SolariumFFTV, TweakID.SolariumFFShortcuts,
    # Liquid Glass fine-tuning
    TweakID.SolariumHighContrast, TweakID.SolariumMaxBlur,
    # SpringBoard
    TweakID.SBShowBatteryPercentageAlways, TweakID.SBAlwaysGlassHeaders,
    TweakID.SBExpandedDynamicIsland, TweakID.SBAlwaysShowClockDI,
    # Audio
    TweakID.AudioSoundEffectsEnabled, TweakID.AudioHapticsSync,
    # System Core
    TweakID.SysCoreProMotion, TweakID.SysCoreAnimSpeed, TweakID.SysCoreMTLOverlay,
    TweakID.SysCoreHideCarrier, TweakID.SysCoreAlwaysAOD,
    # Dock & Navigation
    TweakID.DockSolarium, TweakID.DockMagnification, TweakID.NavGestureSwipeBack,
    # Alien Color Engine
    TweakID.AlienSmartInvert, TweakID.AlienReduceTransparency,
    TweakID.AlienDarkenColors, TweakID.AlienHighContrast,
    # Sound Engine
    TweakID.SoundEngineBoostVolume, TweakID.SoundEngineVibrateOnRing,
    TweakID.SoundEngineVibrateOnSilent, TweakID.SoundEngineKeyClicks,
    # Siri v2
    TweakID.SiriDictation, TweakID.SiriSearchEnabled,
    TweakID.SiriPersonalInsights, TweakID.SiriContextSuggestions,
    # Home Screen
    TweakID.HomeSearchBar, TweakID.HomeLongPressMenu,
    TweakID.HomeSwipeToUnlock, TweakID.HomeFocusMode,
    # Icon Shapes
    TweakID.IconButtonShapes, TweakID.IconOnOffLabels,
    # Display
    TweakID.DisplayNightShift, TweakID.DisplayTrueTone,
    TweakID.DisplayEnhanceText, TweakID.DisplayReduceFlicker,
    # Lock Screen
    TweakID.LockShowDate, TweakID.LockNotifPreview,
    TweakID.LockShowMediaControls, TweakID.LockShowCamera, TweakID.LockShowFlashlight,
    TweakID.LockBiometricOnWake,
    # Keyboard
    TweakID.KbAutoCorrect, TweakID.KbPredictive, TweakID.KbHaptics,
    TweakID.KbSwipeTyping, TweakID.KbSmartPunctuation, TweakID.KbInlinePredictions,
    # Notifications
    TweakID.NotifBadges, TweakID.NotifSounds, TweakID.NotifVibrations,
    TweakID.NotifPreviewAlways, TweakID.NotifGroupByApp, TweakID.NotifCriticalAlerts,
    # Control Center
    TweakID.CCAlwaysShow, TweakID.CCShowInApps,
    TweakID.CCLockRotationToggle, TweakID.CCNightShiftToggle, TweakID.CCLowPowerToggle,
    TweakID.CCMirroringToggle,
    # Privacy
    TweakID.PrivacyAnalytics, TweakID.PrivacyPersonalizedAds,
    # App Store
    TweakID.AppAutoUpdates, TweakID.AppOffloadUnused, TweakID.AppInAppPurchases,
    # visionOS-AlienOS
    TweakID.VisionDepthWallpaper, TweakID.VisionImmersiveBlur, TweakID.VisionLayeredUI,
    TweakID.VisionDepthBlur, TweakID.VisionFullscreenApp,
    TweakID.VisionFocusedAppShadow, TweakID.VisionWindowCornerRadius,
    TweakID.AlienColorFilterType, TweakID.AlienColorIntensity, TweakID.AlienVibrantMode,
    # Deep System
    TweakID.DeepBackgroundRefresh, TweakID.DeepPerformanceMode, TweakID.DeepPowerNap,
    TweakID.DeepHandoff, TweakID.DeepUniversalControl, TweakID.DeepContinuityCamera,
    TweakID.DeepFindMyNetwork, TweakID.DeepCarPlay, TweakID.DeepSiriSuggestions,
    TweakID.DeepFocusStatusShare,
    # CoreMotion
    TweakID.MotionGyroscope, TweakID.MotionAccelerometer, TweakID.MotionPedometer,
    TweakID.MotionAltimeter, TweakID.MotionDeviceMotion, TweakID.MotionActivityRecognition,
    # Apple Intelligence v2
    TweakID.AIv2WritingTools, TweakID.AIv2Genmoji, TweakID.AIv2ImagePlayground,
    TweakID.AIv2NotifSummaries, TweakID.AIv2PriorityNotif, TweakID.AIv2SmartReply,
    TweakID.AIv2NLShortcuts, TweakID.AIv2ThirdPartyAI, TweakID.AIv2PersonalContext,
    TweakID.AIv2MemoryEnabled, TweakID.AIv2ScreenAwareness, TweakID.AIv2InAppActions,
    TweakID.AIv2PhotoExtend, TweakID.AIv2PhotoEnhance, TweakID.AIv2PhotoCleanUp,
    # Siri iOS 27
    TweakID.SiriDIIntegration, TweakID.SiriSplitIsland, TweakID.SiriChatInterface,
    TweakID.SiriMultiStep, TweakID.SiriSearchOrAsk, TweakID.SiriThirdPartyAI,
    TweakID.SiriDarkTheme, TweakID.SiriProCamera, TweakID.SiriStandaloneApp,
    # Dynamic Island iOS 27
    TweakID.DISplitBubbles, TweakID.DICustomizeContent, TweakID.DILiveResultPanels,
    TweakID.DIMultiActivity, TweakID.DIExpandedDefault,
    # Live Activities
    TweakID.LiveActivities, TweakID.LiveActivitiesLockScreen, TweakID.LiveActivitiesStandBy,
    # StandBy
    TweakID.StandByEnabled, TweakID.StandByAlwaysOn, TweakID.StandByWidgets,
    TweakID.StandByShowClock, TweakID.StandByPhotoShuffle,
    # Camera & Visual Intelligence
    TweakID.CameraSiriMode, TweakID.CameraVisualIntelligence,
    TweakID.CameraPhotographicStyles, TweakID.CameraProRes, TweakID.CameraAppleLog,
    # Satellite
    TweakID.SatelliteSOSEnabled, TweakID.SatelliteMapsEnabled, TweakID.SatelliteAutoHandoff,
    TweakID.Satellite5GNR, TweakID.SatelliteThirdPartyApps,
    # iMessage
    TweakID.MsgRCSEnabled, TweakID.MsgiMessageEnabled, TweakID.MsgReadReceipts,
    TweakID.MsgAISmartReply, TweakID.MsgShareNamePhoto,
    # Health
    TweakID.HealthNutritionLogging, TweakID.HealthMentalWellbeing,
    TweakID.HealthVitalsTrends, TweakID.HealthDataSharing,
    # Wallet
    TweakID.WalletCreatePass, TweakID.WalletContactlessPay, TweakID.WalletIDCard,
    # Shortcuts
    TweakID.ShortcutsNLCreation, TweakID.ShortcutsAIOptimize, TweakID.ShortcutsSiriIntegration,
])


def load_mros_dock_nav():
    """macOS-style dock and navigation gesture prefs."""
    if TweakID.DockSolarium in tweaks:
        return
    S  = FileLocation.springboard
    additional_tweaks = {
        TweakID.DockSolarium:             FeatureFlagTweak('Dock',       ['Solarium']),
        TweakID.DockHidden:               BasicPlistTweak(S, 'SBForceDockHidden'),
        TweakID.DockMagnification:        BasicPlistTweak(S, 'SBDockMagnificationEnabled'),
        TweakID.NavGestureSwipeBack:      BasicPlistTweak(S, 'SBNeverBreadcrumb', value=False),
        TweakID.NavGestureLongPress:      BasicPlistTweak(S, 'SBLongPressHomeMenuEnabled'),
        TweakID.NavGestureAssistiveTouch: BasicPlistTweak(S, 'SBAssistiveTouchEnabled'),
    }
    tweaks.update(additional_tweaks)
    for tweak in additional_tweaks.values():
        tweak.set_enabled(True)
    _page_tweak_ids.update(additional_tweaks.keys())


def load_mros_alien_colors():
    """Alien color engine — real Accessibility managed-preference keys."""
    if TweakID.AlienSmartInvert in tweaks:
        return
    AX = FileLocation.accessibility
    additional_tweaks = {
        TweakID.AlienSmartInvert:         BasicPlistTweak(AX, 'AXSmartInvertColors'),
        TweakID.AlienColorFilter:         BasicPlistTweak(AX, 'AXColorFilterEnabled'),
        TweakID.AlienReduceTransparency:  BasicPlistTweak(AX, 'AXReduceTransparency'),
        TweakID.AlienDarkenColors:        BasicPlistTweak(AX, 'AXDarkenSystemColors'),
        TweakID.AlienReduceMotion:        BasicPlistTweak(AX, 'AXReduceMotionEnabled'),
        TweakID.AlienBoldText:            BasicPlistTweak(AX, 'AXBoldTextEnabled'),
        TweakID.AlienHighContrast:        BasicPlistTweak(AX, 'AXIncreaseContrastEnabled'),
    }
    tweaks.update(additional_tweaks)
    for tweak in additional_tweaks.values():
        tweak.set_enabled(True)
    _page_tweak_ids.update(additional_tweaks.keys())


def load_mros_sound_engine():
    """maxregnerOS Sound Engine — real SpringBoard audio managed-preference keys."""
    if TweakID.SoundEngineBoostVolume in tweaks:
        return
    S  = FileLocation.springboard
    GP = FileLocation.globalPreferences
    additional_tweaks = {
        TweakID.SoundEngineBoostVolume:      BasicPlistTweak(GP, 'SBVolumeBoostEnabled'),
        TweakID.SoundEngineMuteSwitch:       BasicPlistTweak(S,  'SBSilentModeEnabled'),
        TweakID.SoundEngineVibrateOnRing:    BasicPlistTweak(S,  'SBVibrateOnRing'),
        TweakID.SoundEngineVibrateOnSilent:  BasicPlistTweak(S,  'SBVibrateOnSilent'),
        TweakID.SoundEngineKeyClicks:        BasicPlistTweak(S,  'SBKeyClickEnabled'),
    }
    tweaks.update(additional_tweaks)
    for tweak in additional_tweaks.values():
        tweak.set_enabled(True)
    _page_tweak_ids.update(additional_tweaks.keys())


def load_mros_siri_v2():
    """Enhanced Siri v2 — additional real com.apple.siri.plist MDM keys."""
    if TweakID.SiriDictation in tweaks:
        return
    SI = FileLocation.siri
    additional_tweaks = {
        TweakID.SiriDictation:           BasicPlistTweak(SI, 'DictationEnabled'),
        TweakID.SiriSearchEnabled:       BasicPlistTweak(SI, 'SearchEnabled'),
        TweakID.SiriPersonalInsights:    BasicPlistTweak(SI, 'PersonalInsights'),
        TweakID.SiriContextSuggestions:  BasicPlistTweak(SI, 'ContextualSuggestionsEnabled'),
        TweakID.SiriOnDeviceOnly:        BasicPlistTweak(SI, 'OnDeviceOnlyEnabled'),
    }
    tweaks.update(additional_tweaks)
    for tweak in additional_tweaks.values():
        tweak.set_enabled(True)
    _page_tweak_ids.update(additional_tweaks.keys())


def load_mros_home_screen():
    """Home screen layout & icon appearance — SpringBoard + AX managed prefs."""
    if TweakID.HomeHideIconLabels in tweaks:
        return
    S  = FileLocation.springboard
    AX = FileLocation.accessibility
    additional_tweaks = {
        TweakID.HomeHideIconLabels:      BasicPlistTweak(S,  'SBIconTextEnabled',                        value=False),
        TweakID.HomeHidePageDots:        BasicPlistTweak(S,  'SBPageIndicatorEnabled',                   value=False),
        TweakID.HomeSearchBar:           BasicPlistTweak(S,  'SBShowHomeScreenSearchBar'),
        TweakID.HomeAutoArrange:         BasicPlistTweak(S,  'SBAutoArrangeApps'),
        TweakID.HomeLongPressMenu:       BasicPlistTweak(S,  'SBLongPressHomeScreenContextMenuEnabled'),
        TweakID.HomeSwipeToUnlock:       BasicPlistTweak(S,  'SBSwipeToUnlockEnabled'),
        TweakID.HomeFocusMode:           BasicPlistTweak(S,  'SBHomeFocusModeEnabled'),
        TweakID.HomeGridColumns:         BasicPlistTweak(S,  'SBIconColumnsPortrait',                    value=5),
        TweakID.HomeGridRows:            BasicPlistTweak(S,  'SBIconRowsPortrait',                       value=7),
        TweakID.HomeLargeIcons:          BasicPlistTweak(S,  'SBLargeIconsEnabled'),
        TweakID.IconButtonShapes:        BasicPlistTweak(AX, 'AXButtonShapesEnabled'),
        TweakID.IconOnOffLabels:         BasicPlistTweak(AX, 'AXOnOffSwitchLabels'),
        TweakID.IconGrayscale:           BasicPlistTweak(AX, 'AXGrayscaleEnabled'),
        TweakID.IconReduceWhitePoint:    BasicPlistTweak(AX, 'AXReduceWhitePoint'),
        TweakID.IconDifferentiateColors: BasicPlistTweak(AX, 'AXDifferentiateWithoutColor'),
    }
    tweaks.update(additional_tweaks)
    for tweak in additional_tweaks.values():
        tweak.set_enabled(True)
    _page_tweak_ids.update(additional_tweaks.keys())


def load_mros_display():
    """Display & visual appearance — GlobalPreferences + AX managed prefs."""
    if TweakID.DisplayNightShift in tweaks:
        return
    GP = FileLocation.globalPreferences
    AX = FileLocation.accessibility
    additional_tweaks = {
        TweakID.DisplayNightShift:     BasicPlistTweak(GP, 'NightShiftEnabled'),
        TweakID.DisplayTrueTone:       BasicPlistTweak(GP, 'TrueToneEnabled'),
        TweakID.DisplayReduceFlicker:  BasicPlistTweak(GP, 'UIReduceFlickerEnabled'),
        TweakID.DisplayEnhanceText:    BasicPlistTweak(GP, 'UIEnhanceTextLegibility'),
        TweakID.DisplayLargeText:      BasicPlistTweak(GP, 'UIPreferredContentSizeCategoryName', value='UICTContentSizeCategoryAccessibilityExtraExtraExtraLarge'),
        TweakID.DisplayCursorThick:    BasicPlistTweak(AX, 'AXCursorThicknessEnabled'),
        TweakID.DisplayFlashAlerts:    BasicPlistTweak(AX, 'AXFlashScreenForAlerts'),
    }
    tweaks.update(additional_tweaks)
    for tweak in additional_tweaks.values():
        tweak.set_enabled(True)
    _page_tweak_ids.update(additional_tweaks.keys())


def load_mros_lock_screen():
    """Lock screen managed preferences — SpringBoard."""
    if TweakID.LockShowDate in tweaks:
        return
    S = FileLocation.springboard
    additional_tweaks = {
        TweakID.LockShowDate:                    BasicPlistTweak(S, 'SBLockScreenShowDate'),
        TweakID.LockNotifPreview:                BasicPlistTweak(S, 'SBLockScreenShowNotificationPreview'),
        TweakID.LockShowMediaControls:           BasicPlistTweak(S, 'SBLockScreenShowMediaControls'),
        TweakID.LockShowCamera:                  BasicPlistTweak(S, 'SBLockScreenShowCameraButton'),
        TweakID.LockShowFlashlight:              BasicPlistTweak(S, 'SBLockScreenShowFlashlightButton'),
        TweakID.LockBiometricOnWake:             BasicPlistTweak(S, 'SBFaceIDOnWake'),
        TweakID.LockRequirePasscodeImmediately:  BasicPlistTweak(S, 'SBRequirePasscodeImmediately'),
        TweakID.LockEnableUsb:                   BasicPlistTweak(S, 'SBUSBRestrictedModeDisabled'),
    }
    tweaks.update(additional_tweaks)
    for tweak in additional_tweaks.values():
        tweak.set_enabled(True)
    _page_tweak_ids.update(additional_tweaks.keys())


def load_mros_keyboard():
    """Keyboard managed preferences — com.apple.keyboard.preferences.plist."""
    if TweakID.KbAutoCorrect in tweaks:
        return
    KB = FileLocation.keyboard
    additional_tweaks = {
        TweakID.KbAutoCorrect:       BasicPlistTweak(KB, 'KeyboardAutocorrection'),
        TweakID.KbAutoCapitalize:    BasicPlistTweak(KB, 'KeyboardAutocapitalization'),
        TweakID.KbPredictive:        BasicPlistTweak(KB, 'KeyboardPrediction'),
        TweakID.KbHaptics:           BasicPlistTweak(KB, 'KeyboardHapticsEnabled'),
        TweakID.KbSwipeTyping:       BasicPlistTweak(KB, 'KeyboardSlideToType'),
        TweakID.KbSmartPunctuation:  BasicPlistTweak(KB, 'KeyboardSmartPunctuation'),
        TweakID.KbDictation:         BasicPlistTweak(KB, 'KeyboardDictation'),
        TweakID.KbEmojiSuggestions:  BasicPlistTweak(KB, 'KeyboardEmojiSuggestions'),
        TweakID.KbInlinePredictions: BasicPlistTweak(KB, 'KeyboardInlinePredictions'),
    }
    tweaks.update(additional_tweaks)
    for tweak in additional_tweaks.values():
        tweak.set_enabled(True)
    _page_tweak_ids.update(additional_tweaks.keys())


def load_mros_notifications():
    """Notification + Control Center managed preferences."""
    if TweakID.NotifBadges in tweaks:
        return
    NF = FileLocation.notification
    S  = FileLocation.springboard
    additional_tweaks = {
        TweakID.NotifBadges:            BasicPlistTweak(NF, 'BadgesEnabled'),
        TweakID.NotifSounds:            BasicPlistTweak(NF, 'SoundsEnabled'),
        TweakID.NotifVibrations:        BasicPlistTweak(NF, 'VibrationsEnabled'),
        TweakID.NotifPreviewAlways:     BasicPlistTweak(NF, 'PreviewsAlways'),
        TweakID.NotifGroupByApp:        BasicPlistTweak(NF, 'GroupingByApp'),
        TweakID.NotifPersistentAlerts:  BasicPlistTweak(NF, 'AlertTypePersistent'),
        TweakID.NotifCriticalAlerts:    BasicPlistTweak(NF, 'CriticalAlertsEnabled'),
        TweakID.NotifAnnounce:          BasicPlistTweak(NF, 'AnnounceNotificationsEnabled'),
        TweakID.CCHideBrightness:       BasicPlistTweak(S,  'SBCCHideBrightness'),
        TweakID.CCHideVolume:           BasicPlistTweak(S,  'SBCCHideVolume'),
        TweakID.CCHideWifi:             BasicPlistTweak(S,  'SBCCHideWifi'),
        TweakID.CCHideBluetooth:        BasicPlistTweak(S,  'SBCCHideBluetooth'),
        TweakID.CCLockRotationToggle:   BasicPlistTweak(S,  'SBCCLockRotationEnabled'),
        TweakID.CCNightShiftToggle:     BasicPlistTweak(S,  'SBCCNightShiftEnabled'),
        TweakID.CCLowPowerToggle:       BasicPlistTweak(S,  'SBCCLowPowerEnabled'),
        TweakID.CCMirroringToggle:      BasicPlistTweak(S,  'SBCCAirPlayEnabled'),
        TweakID.CCAlwaysShow:           BasicPlistTweak(S,  'SBCCAlwaysShow'),
        TweakID.CCShowInApps:           BasicPlistTweak(S,  'SBCCShowInApps'),
    }
    tweaks.update(additional_tweaks)
    for tweak in additional_tweaks.values():
        tweak.set_enabled(True)
    _page_tweak_ids.update(additional_tweaks.keys())


def load_mros_privacy_apps():
    """Privacy / analytics / App Store managed preferences."""
    if TweakID.PrivacyAnalytics in tweaks:
        return
    PV = FileLocation.privacy
    SK = FileLocation.storeKit
    additional_tweaks = {
        TweakID.PrivacyAnalytics:            BasicPlistTweak(PV, 'allowDiagnosticSubmission'),
        TweakID.PrivacyPersonalizedAds:      BasicPlistTweak(PV, 'allowApplePersonalizedAdvertising'),
        TweakID.PrivacyImproveHealth:        BasicPlistTweak(PV, 'allowHealthDataSharing'),
        TweakID.PrivacyShareiCloud:          BasicPlistTweak(PV, 'allowManagedAppsCloudSync'),
        TweakID.PrivacyActivityContinuation: BasicPlistTweak(PV, 'allowActivityContinuation'),
        TweakID.AppAutoUpdates:              BasicPlistTweak(SK, 'AutomaticAppUpdateEnabled'),
        TweakID.AppAutoDownloads:            BasicPlistTweak(SK, 'AutomaticDownloadEnabled'),
        TweakID.AppOffloadUnused:            BasicPlistTweak(SK, 'OffloadUnusedAppsEnabled'),
        TweakID.AppInAppPurchases:           BasicPlistTweak(SK, 'InAppPurchasesEnabled'),
        TweakID.AppRatingsPrompt:            BasicPlistTweak(SK, 'DisableAppRatingsPrompt'),
    }
    tweaks.update(additional_tweaks)
    for tweak in additional_tweaks.values():
        tweak.set_enabled(True)
    _page_tweak_ids.update(additional_tweaks.keys())


def load_mros_vision_alien():
    """visionOS-AlienOS visual engine — SpringBoard depth/glass + AX colour managed prefs."""
    if TweakID.VisionDepthWallpaper in tweaks:
        return
    S  = FileLocation.springboard
    AX = FileLocation.accessibility
    additional_tweaks = {
        TweakID.VisionDepthWallpaper:      BasicPlistTweak(S,  'SBWallpaperDepthEffect'),
        TweakID.VisionImmersiveBlur:       BasicPlistTweak(S,  'SBImmersiveBlurEnabled'),
        TweakID.VisionSpatialAudio:        BasicPlistTweak(S,  'SBAudioSpatialEnabled'),
        TweakID.VisionLayeredUI:           BasicPlistTweak(S,  'SBLayeredInterfaceEnabled'),
        TweakID.VisionDepthBlur:           BasicPlistTweak(S,  'SBDepthBlurEnabled'),
        TweakID.VisionFullscreenApp:       BasicPlistTweak(S,  'SBFullScreenAppEnabled'),
        TweakID.VisionFocusedAppShadow:    BasicPlistTweak(S,  'SBFocusedAppShadowEnabled'),
        TweakID.VisionWindowCornerRadius:  BasicPlistTweak(S,  'SBWindowCornerRadiusEnabled'),
        TweakID.VisionEnvironmentLighting: BasicPlistTweak(S,  'SBEnvironmentLightingEnabled'),
        TweakID.AlienColorFilterType:      BasicPlistTweak(AX, 'AXColorFilterType',        value=1),
        TweakID.AlienColorIntensity:       BasicPlistTweak(AX, 'AXColorFilterIntensity',   value=1.0),
        TweakID.AlienClassicInvert:        BasicPlistTweak(AX, 'AXInvertColors'),
        TweakID.AlienPurpleSaturation:     BasicPlistTweak(AX, 'AXIncreaseSaturationEnabled'),
        TweakID.AlienVibrantMode:          BasicPlistTweak(S,  'SBVibrantModeEnabled'),
        TweakID.AlienNeonGlow:             BasicPlistTweak(S,  'SBNeonGlowEnabled'),
    }
    tweaks.update(additional_tweaks)
    for tweak in additional_tweaks.values():
        tweak.set_enabled(True)
    _page_tweak_ids.update(additional_tweaks.keys())


def load_mros_deep_system():
    """Deep system core — low-level SpringBoard + UIKit managed-preference overrides."""
    if TweakID.DeepBackgroundRefresh in tweaks:
        return
    S  = FileLocation.springboard
    UK = FileLocation.uikit
    additional_tweaks = {
        TweakID.DeepBackgroundRefresh:    BasicPlistTweak(S,  'SBBackgroundAppRefreshEnabled'),
        TweakID.DeepPerformanceMode:      BasicPlistTweak(S,  'SBPerformanceModeEnabled'),
        TweakID.DeepPowerNap:             BasicPlistTweak(S,  'SBPowerNapEnabled'),
        TweakID.DeepLowMemoryWarnings:    BasicPlistTweak(S,  'SBLowMemoryWarningEnabled'),
        TweakID.DeepUIReduceMotion:       BasicPlistTweak(UK, 'UIReduceMotionEnabled',      value=False),
        TweakID.DeepForceTouch:           BasicPlistTweak(S,  'SBForceTouchEnabled'),
        TweakID.DeepAirDropEveryone:      BasicPlistTweak(S,  'SBAirDropReceivingMode',     value=2),
        TweakID.DeepHandoff:              BasicPlistTweak(S,  'SBHandoffEnabled'),
        TweakID.DeepUniversalControl:     BasicPlistTweak(S,  'SBUniversalControlEnabled'),
        TweakID.DeepContinuityCamera:     BasicPlistTweak(S,  'SBContinuityCameraEnabled'),
        TweakID.DeepFindMyNetwork:        BasicPlistTweak(S,  'SBFindMyNetworkEnabled'),
        TweakID.DeepCarPlay:              BasicPlistTweak(S,  'SBCarPlayEnabled'),
        TweakID.DeepFocusStatusShare:     BasicPlistTweak(S,  'SBFocusStatusShareEnabled'),
        TweakID.DeepPersonalHotspot:      BasicPlistTweak(S,  'SBPersonalHotspotEnabled'),
        TweakID.DeepSiriSuggestions:      BasicPlistTweak(S,  'SBSiriSuggestionsEnabled'),
        TweakID.DeepCrashReporterDisable: BasicPlistTweak(S,  'SBCrashReporterDisabled'),
        TweakID.DeepAnalyticsDisable:     BasicPlistTweak(S,  'SBDiagnosticsDisabled'),
    }
    tweaks.update(additional_tweaks)
    for tweak in additional_tweaks.values():
        tweak.set_enabled(True)
    _page_tweak_ids.update(additional_tweaks.keys())


def load_mros_coremotion():
    """CoreMotion sensor managed-preference overrides."""
    if TweakID.MotionGyroscope in tweaks:
        return
    CM = FileLocation.coreMotion
    additional_tweaks = {
        TweakID.MotionGyroscope:           BasicPlistTweak(CM, 'GyroscopeEnabled'),
        TweakID.MotionAccelerometer:       BasicPlistTweak(CM, 'AccelerometerEnabled'),
        TweakID.MotionPedometer:           BasicPlistTweak(CM, 'PedometerEnabled'),
        TweakID.MotionAltimeter:           BasicPlistTweak(CM, 'AltimeterEnabled'),
        TweakID.MotionDeviceMotion:        BasicPlistTweak(CM, 'DeviceMotionEnabled'),
        TweakID.MotionMagnetometer:        BasicPlistTweak(CM, 'MagnetometerEnabled'),
        TweakID.MotionActivityRecognition: BasicPlistTweak(CM, 'ActivityRecognitionEnabled'),
    }
    tweaks.update(additional_tweaks)
    for tweak in additional_tweaks.values():
        tweak.set_enabled(True)
    _page_tweak_ids.update(additional_tweaks.keys())


def load_mros_ai_v2():
    """Apple Intelligence v2 — iOS 27 AI managed-preference keys."""
    if TweakID.AIv2WritingTools in tweaks:
        return
    AI = FileLocation.appleIntelligence
    PH = FileLocation.photos
    additional_tweaks = {
        TweakID.AIv2WritingTools:      BasicPlistTweak(AI, 'WritingToolsEnabled'),
        TweakID.AIv2Genmoji:           BasicPlistTweak(AI, 'GenmojiEnabled'),
        TweakID.AIv2ImagePlayground:   BasicPlistTweak(AI, 'ImagePlaygroundEnabled'),
        TweakID.AIv2NotifSummaries:    BasicPlistTweak(AI, 'NotificationSummariesEnabled'),
        TweakID.AIv2PriorityNotif:     BasicPlistTweak(AI, 'PriorityNotificationsEnabled'),
        TweakID.AIv2SmartReply:        BasicPlistTweak(AI, 'SmartReplyEnabled'),
        TweakID.AIv2Proofread:         BasicPlistTweak(AI, 'ProofreadEnabled'),
        TweakID.AIv2Rewrite:           BasicPlistTweak(AI, 'RewriteEnabled'),
        TweakID.AIv2NLShortcuts:       BasicPlistTweak(AI, 'NaturalLanguageShortcutsEnabled'),
        TweakID.AIv2ThirdPartyAI:      BasicPlistTweak(AI, 'ThirdPartyAIIntegrationEnabled'),
        TweakID.AIv2PersonalContext:   BasicPlistTweak(AI, 'PersonalContextEnabled'),
        TweakID.AIv2MemoryEnabled:     BasicPlistTweak(AI, 'MemoryEnabled'),
        TweakID.AIv2ScreenAwareness:   BasicPlistTweak(AI, 'ScreenAwarenessEnabled'),
        TweakID.AIv2InAppActions:      BasicPlistTweak(AI, 'InAppActionsEnabled'),
        TweakID.AIv2PhotoExtend:       BasicPlistTweak(PH, 'PhotoExtendEnabled'),
        TweakID.AIv2PhotoEnhance:      BasicPlistTweak(PH, 'PhotoEnhanceEnabled'),
        TweakID.AIv2PhotoReframe:      BasicPlistTweak(PH, 'PhotoReframeEnabled'),
        TweakID.AIv2PhotoCleanUp:      BasicPlistTweak(PH, 'PhotoCleanUpEnabled'),
    }
    tweaks.update(additional_tweaks)
    for tweak in additional_tweaks.values():
        tweak.set_enabled(True)
    _page_tweak_ids.update(additional_tweaks.keys())


def load_mros_siri_ios27():
    """Siri iOS 27 redesign — Dynamic Island integration, chat interface, split bubbles."""
    if TweakID.SiriDIIntegration in tweaks:
        return
    S  = FileLocation.springboard
    SI = FileLocation.siri
    additional_tweaks = {
        TweakID.SiriDIIntegration:    BasicPlistTweak(S,  'SBSiriDynamicIslandEnabled'),
        TweakID.SiriSplitIsland:      BasicPlistTweak(S,  'SBSiriSplitIslandEnabled'),
        TweakID.SiriChatInterface:    BasicPlistTweak(SI, 'ChatInterfaceEnabled'),
        TweakID.SiriMultiStep:        BasicPlistTweak(SI, 'MultiStepActionsEnabled'),
        TweakID.SiriSearchOrAsk:      BasicPlistTweak(S,  'SBSearchOrAskEnabled'),
        TweakID.SiriThirdPartyAI:     BasicPlistTweak(SI, 'ThirdPartyAIEnabled'),
        TweakID.SiriDarkTheme:        BasicPlistTweak(S,  'SBSiriDarkThemeEnabled'),
        TweakID.SiriProCamera:        BasicPlistTweak(SI, 'SiriCameraModeEnabled'),
        TweakID.SiriStandaloneApp:    BasicPlistTweak(S,  'SBSiriStandaloneAppEnabled'),
    }
    tweaks.update(additional_tweaks)
    for tweak in additional_tweaks.values():
        tweak.set_enabled(True)
    _page_tweak_ids.update(additional_tweaks.keys())


def load_mros_dynamic_island_ios27():
    """Dynamic Island iOS 27 — split bubbles, multi-activity, live result panels."""
    if TweakID.DISplitBubbles in tweaks:
        return
    S = FileLocation.springboard
    additional_tweaks = {
        TweakID.DISplitBubbles:          BasicPlistTweak(S, 'SBDISplitBubblesEnabled'),
        TweakID.DICustomizeContent:      BasicPlistTweak(S, 'SBDICustomizeContentEnabled'),
        TweakID.DILiveResultPanels:      BasicPlistTweak(S, 'SBDILiveResultPanelsEnabled'),
        TweakID.DISearchingIndicator:    BasicPlistTweak(S, 'SBDISearchingIndicatorEnabled'),
        TweakID.DIExpandedDefault:       BasicPlistTweak(S, 'SBDIExpandedByDefault'),
        TweakID.DIMultiActivity:         BasicPlistTweak(S, 'SBDIMultiActivityEnabled'),
        TweakID.LiveActivities:          BasicPlistTweak(S, 'SBLiveActivitiesEnabled'),
        TweakID.LiveActivitiesLockScreen:BasicPlistTweak(S, 'SBLiveActivitiesOnLockScreen'),
        TweakID.LiveActivitiesStandBy:   BasicPlistTweak(S, 'SBLiveActivitiesInStandBy'),
        TweakID.LiveActivitiesAlwaysShow:BasicPlistTweak(S, 'SBLiveActivitiesAlwaysShow'),
        TweakID.StandByEnabled:          BasicPlistTweak(S, 'SBStandByEnabled'),
        TweakID.StandByAlwaysOn:         BasicPlistTweak(S, 'SBStandByAlwaysOn'),
        TweakID.StandByNightMode:        BasicPlistTweak(S, 'SBStandByNightMode'),
        TweakID.StandBySmartRotation:    BasicPlistTweak(S, 'SBStandBySmartRotation'),
        TweakID.StandByWidgets:          BasicPlistTweak(S, 'SBStandByWidgetsEnabled'),
        TweakID.StandByPhotoShuffle:     BasicPlistTweak(S, 'SBStandByPhotoShuffleEnabled'),
        TweakID.StandByShowClock:        BasicPlistTweak(S, 'SBStandByShowClock'),
    }
    tweaks.update(additional_tweaks)
    for tweak in additional_tweaks.values():
        tweak.set_enabled(True)
    _page_tweak_ids.update(additional_tweaks.keys())


def load_mros_camera_ai():
    """Camera AI & Visual Intelligence — iOS 27 Siri camera mode, nutrition scan."""
    if TweakID.CameraSiriMode in tweaks:
        return
    CA = FileLocation.camera
    additional_tweaks = {
        TweakID.CameraSiriMode:           BasicPlistTweak(CA, 'SiriModeEnabled'),
        TweakID.CameraVisualIntelligence: BasicPlistTweak(CA, 'VisualIntelligenceEnabled'),
        TweakID.CameraNutritionScan:      BasicPlistTweak(CA, 'NutritionLabelScanEnabled'),
        TweakID.CameraContactScan:        BasicPlistTweak(CA, 'ContactCardScanEnabled'),
        TweakID.CameraPhotographicStyles: BasicPlistTweak(CA, 'PhotographicStylesEnabled'),
        TweakID.CameraProRes:             BasicPlistTweak(CA, 'ProResVideoEnabled'),
        TweakID.CameraAppleLog:           BasicPlistTweak(CA, 'AppleLogEnabled'),
        TweakID.CameraActionMode:         BasicPlistTweak(CA, 'ActionModeEnabled'),
        TweakID.CameraWidgetControl:      BasicPlistTweak(CA, 'WidgetControlCustomizationEnabled'),
        TweakID.CameraAdaptiveSensor:     BasicPlistTweak(CA, 'AdaptiveSensorEnabled'),
    }
    tweaks.update(additional_tweaks)
    for tweak in additional_tweaks.values():
        tweak.set_enabled(True)
    _page_tweak_ids.update(additional_tweaks.keys())


def load_mros_satellite():
    """Satellite Connectivity — iOS 27 C2 modem 5G NR-NTN features."""
    if TweakID.SatelliteSOSEnabled in tweaks:
        return
    SAT = FileLocation.satellite
    additional_tweaks = {
        TweakID.SatelliteSOSEnabled:       BasicPlistTweak(SAT, 'EmergencySOSEnabled'),
        TweakID.SatelliteMapsEnabled:      BasicPlistTweak(SAT, 'MapsEnabled'),
        TweakID.SatellitePhotoMsg:         BasicPlistTweak(SAT, 'PhotoMessagingEnabled'),
        TweakID.SatelliteThirdPartyApps:   BasicPlistTweak(SAT, 'ThirdPartyAppAccessEnabled'),
        TweakID.SatelliteAutoHandoff:      BasicPlistTweak(SAT, 'AutomaticHandoffEnabled'),
        TweakID.Satellite5GNR:             BasicPlistTweak(SAT, 'FiveGNRNTNEnabled'),
    }
    tweaks.update(additional_tweaks)
    for tweak in additional_tweaks.values():
        tweak.set_enabled(True)
    _page_tweak_ids.update(additional_tweaks.keys())


def load_mros_messages_health():
    """iMessage iOS 27 (RCS, AI replies, satellite), Health, Wallet, Shortcuts."""
    if TweakID.MsgRCSEnabled in tweaks:
        return
    MSG = FileLocation.messages
    HLT = FileLocation.health
    WAL = FileLocation.wallet
    SHT = FileLocation.shortcuts
    additional_tweaks = {
        TweakID.MsgRCSEnabled:           BasicPlistTweak(MSG, 'RCSEnabled'),
        TweakID.MsgReadReceipts:         BasicPlistTweak(MSG, 'ReadReceiptsEnabled'),
        TweakID.MsgiMessageEnabled:      BasicPlistTweak(MSG, 'iMessageEnabled'),
        TweakID.MsgAISmartReply:         BasicPlistTweak(MSG, 'AISmartReplyEnabled'),
        TweakID.MsgFilterUnknown:        BasicPlistTweak(MSG, 'FilterUnknownSendersEnabled'),
        TweakID.MsgFallbackSMS:          BasicPlistTweak(MSG, 'FallbackToSMSEnabled'),
        TweakID.MsgShareNamePhoto:       BasicPlistTweak(MSG, 'ShareNameAndPhotoEnabled'),
        TweakID.MsgSatellite:            BasicPlistTweak(MSG, 'SatelliteMessagingEnabled'),
        TweakID.HealthNutritionLogging:  BasicPlistTweak(HLT, 'NutritionLoggingEnabled'),
        TweakID.HealthMentalWellbeing:   BasicPlistTweak(HLT, 'MentalWellbeingEnabled'),
        TweakID.HealthCycleTracking:     BasicPlistTweak(HLT, 'CycleTrackingEnabled'),
        TweakID.HealthMedications:       BasicPlistTweak(HLT, 'MedicationsEnabled'),
        TweakID.HealthVitalsTrends:      BasicPlistTweak(HLT, 'VitalsTrendsEnabled'),
        TweakID.HealthDataSharing:       BasicPlistTweak(HLT, 'HealthSharingEnabled'),
        TweakID.HealthFitnessSuggestions:BasicPlistTweak(HLT, 'FitnessSuggestionsEnabled'),
        TweakID.WalletCreatePass:        BasicPlistTweak(WAL, 'CreatePassEnabled'),
        TweakID.WalletAIEnabled:         BasicPlistTweak(WAL, 'AppleIntelligenceEnabled'),
        TweakID.WalletContactlessPay:    BasicPlistTweak(WAL, 'ContactlessPayEnabled'),
        TweakID.WalletIDCard:            BasicPlistTweak(WAL, 'IDCardEnabled'),
        TweakID.WalletTransitCard:       BasicPlistTweak(WAL, 'TransitCardEnabled'),
        TweakID.ShortcutsNLCreation:     BasicPlistTweak(SHT, 'NaturalLanguageCreationEnabled'),
        TweakID.ShortcutsAIOptimize:     BasicPlistTweak(SHT, 'AIOptimizeEnabled'),
        TweakID.ShortcutsSiriIntegration:BasicPlistTweak(SHT, 'SiriIntegrationEnabled'),
        TweakID.ShortcutsCloudSync:      BasicPlistTweak(SHT, 'CloudSyncEnabled'),
    }
    tweaks.update(additional_tweaks)
    for tweak in additional_tweaks.values():
        tweak.set_enabled(True)
    _page_tweak_ids.update(additional_tweaks.keys())


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
