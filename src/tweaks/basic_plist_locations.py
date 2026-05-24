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

    # Siri managed preferences (real Apple MDM domain)
    siri = "/var/Managed Preferences/mobile/com.apple.siri.plist"

    # Accessibility managed preferences (real Apple MDM domain)
    accessibility = "/var/Managed Preferences/mobile/com.apple.Accessibility.plist"

    # Keyboard managed preferences
    keyboard = "/var/Managed Preferences/mobile/com.apple.keyboard.preferences.plist"

    # Notification managed preferences
    notification = "/var/Managed Preferences/mobile/com.apple.UserNotifications.plist"

    # Privacy / analytics managed preferences
    privacy = "/var/Managed Preferences/mobile/com.apple.applicationaccess.plist"

    # AppStore managed preferences
    storeKit = "/var/Managed Preferences/mobile/com.apple.storekit.plist"
