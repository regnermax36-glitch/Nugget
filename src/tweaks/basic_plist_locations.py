from enum import Enum

class FileLocation(Enum):
    # Mobile Gestalt
    resolution = "/var/Managed Preferences/mobile/com.apple.iokit.IOMobileGraphicsFamily.plist"
    mga = "/var/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache/Library/Caches/com.apple.MobileGestalt.plist"

    # Feature Flags
    featureflags = "/var/preferences/FeatureFlags/Global.plist"
    
    # Springboard Options
    springboard = "/var/Managed Preferences/mobile/com.apple.springboard.plist"
    footnote = "/var/containers/Shared/SystemGroup/systemgroup.com.apple.configurationprofiles/Library/ConfigurationProfiles/SharedDeviceConfiguration.plist"
    airdrop = "/var/Managed Preferences/mobile/com.apple.sharingd.plist"
    nanoregistry = "/var/mobile/Library/Preferences/com.apple.NanoRegistry.plist"
    
    # Internal Options
    globalPreferences = "/var/Managed Preferences/mobile/.GlobalPreferences.plist"
    appStore = "/var/Managed Preferences/mobile/com.apple.AppStore.plist"
    backboardd = "/var/Managed Preferences/mobile/com.apple.backboardd.plist"
    coreMotion = "/var/Managed Preferences/mobile/com.apple.CoreMotion.plist"
    pasteboard = "/var/Managed Preferences/mobile/com.apple.Pasteboard.plist"
    notes = "/var/Managed Preferences/mobile/com.apple.mobilenotes.plist"
    uikit = "/var/Managed Preferences/mobile/com.apple.UIKit.plist"

    # Daemons
    disabledDaemons = "/var/db/com.apple.xpc.launchd/disabled.plist"
    screentime = "/var/mobile/Library/Preferences/ScreenTimeAgent.plist"

    # Risky Options
    ota = "/var/Managed Preferences/mobile/com.apple.MobileAsset.plist"

    # iOS 27 Concept & Siri 2.0 – per-app managed preferences
    siri         = "/var/Managed Preferences/mobile/com.apple.siri.plist"
    controlCenter = "/var/Managed Preferences/mobile/com.apple.control-center.plist"
    photos       = "/var/Managed Preferences/mobile/com.apple.mobileslideshow.plist"
    camera       = "/var/Managed Preferences/mobile/com.apple.camera.plist"
    messages     = "/var/Managed Preferences/mobile/com.apple.MobileSMS.plist"
    maps         = "/var/Managed Preferences/mobile/com.apple.Maps.plist"
    safari       = "/var/Managed Preferences/mobile/com.apple.mobilesafari.plist"
    music        = "/var/Managed Preferences/mobile/com.apple.Music.plist"
    phone        = "/var/Managed Preferences/mobile/com.apple.mobilephone.plist"
    calendar     = "/var/Managed Preferences/mobile/com.apple.mobilecal.plist"
    reminders    = "/var/Managed Preferences/mobile/com.apple.reminders.plist"
    podcasts     = "/var/Managed Preferences/mobile/com.apple.podcasts.plist"
    privacy      = "/var/Managed Preferences/mobile/com.apple.privacy.plist"
