from PySide6.QtWidgets import (
    QWidget, QScrollArea, QVBoxLayout, QHBoxLayout,
    QLabel, QCheckBox, QFrame, QSpacerItem, QSizePolicy
)
from PySide6.QtCore import Qt

from ..page import Page
from src.tweaks.tweaks import tweaks, TweakID
from src.tweaks.tweak_loader import load_ios27


# ── helpers ──────────────────────────────────────────────────────────────────

def _section_label(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setStyleSheet(
        "font-size: 16px; font-weight: bold; color: #e8e8e8; margin-top: 10px;")
    return lbl


def _divider() -> QFrame:
    line = QFrame()
    line.setFrameShape(QFrame.Shape.HLine)
    line.setFrameShadow(QFrame.Shadow.Plain)
    line.setStyleSheet("color: #4B4B4B;")
    return line


def _ff(tweak_id: TweakID, title: str, description: str) -> QWidget:
    """Checkbox row for a FeatureFlagTweak (no BookRestore path)."""
    card = QWidget()
    layout = QVBoxLayout(card)
    layout.setContentsMargins(0, 3, 0, 3)
    layout.setSpacing(2)

    chk = QCheckBox(title)
    chk.setStyleSheet("font-size: 14px;")
    chk.toggled.connect(lambda checked, k=tweak_id: tweaks[k].set_enabled(checked))
    layout.addWidget(chk)

    desc = QLabel(description)
    desc.setStyleSheet("font-size: 12px; color: #888888; padding-left: 22px;")
    desc.setWordWrap(True)
    layout.addWidget(desc)

    return card


# ── page class ───────────────────────────────────────────────────────────────

class iOS27Page(Page):
    """iOS 27 Concept + Siri 2.0 – 87 feature-flag tweaks, no BookRestore paths."""

    def __init__(self, ui, stacked_widget):
        super().__init__()
        self.ui = ui

        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(30, 30, 30, 30)
        content_layout.setSpacing(4)
        content_layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        self._build_ui(content_layout)

        content_layout.addItem(
            QSpacerItem(20, 40, QSizePolicy.Policy.Minimum,
                        QSizePolicy.Policy.Expanding))

        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setFrameShape(QFrame.Shape.NoFrame)
        self.scroll_area.setWidget(content_widget)

        stacked_widget.addWidget(self.scroll_area)
        self.page_index = stacked_widget.count() - 1

    # ── UI construction ──────────────────────────────────────────────────────

    def _build_ui(self, layout: QVBoxLayout):

        # ── Siri 2.0 Core ────────────────────────────────────────────────────
        layout.addWidget(_section_label("Siri 2.0"))
        layout.addWidget(_divider())
        layout.addWidget(_ff(TweakID.Siri2FloatingBubble,
            "Siri 2.0 Floating Bubble",
            "Show Siri as a floating orb/bubble instead of the full-screen overlay."))
        layout.addWidget(_ff(TweakID.Siri2AmbientMode,
            "Siri Ambient Always-On Mode",
            "Keep Siri in a low-power ambient listening state when plugged in."))
        layout.addWidget(_ff(TweakID.Siri2VisualResponse,
            "Siri 2.0 Visual Response Animations",
            "Enable the new fluid wave-and-pulse visual feedback during Siri responses."))
        layout.addWidget(_ff(TweakID.Siri2NaturalVoice,
            "Siri Natural Neural Voice",
            "Enable the next-generation neural TTS voice introduced in iOS 27."))
        layout.addWidget(_ff(TweakID.Siri2OnScreenContext,
            "Siri On-Screen Context Awareness",
            "Allow Siri to read and act on content currently visible on screen."))
        layout.addWidget(_ff(TweakID.Siri2CallScreening,
            "Siri Call Screening",
            "Let Siri answer unknown calls and transcribe the caller's message in real time."))
        layout.addWidget(_ff(TweakID.Siri2PersonalHistory,
            "Siri Personal Context / History",
            "Enable cross-session personal context so Siri remembers preferences over time."))
        layout.addWidget(_ff(TweakID.Siri2VisionProStyle,
            "Siri Vision Pro–Style Presentation",
            "Use the visionOS-inspired spatial Siri UI layout on iPhone."))

        # ── Siri 2.0 Advanced ────────────────────────────────────────────────
        layout.addWidget(_section_label("Siri 2.0 – Advanced"))
        layout.addWidget(_divider())
        layout.addWidget(_ff(TweakID.Siri2MultiModal,
            "Siri Multimodal Input",
            "Combine voice and touch input when interacting with Siri simultaneously."))
        layout.addWidget(_ff(TweakID.Siri2OfflineMode,
            "Siri Local Offline Processing",
            "Route basic Siri requests through on-device neural engines with no network."))
        layout.addWidget(_ff(TweakID.Siri2ProactiveCards,
            "Siri Proactive Suggestion Cards",
            "Show contextual Siri suggestion cards on the lock screen and in Spotlight."))
        layout.addWidget(_ff(TweakID.Siri2AppIntents2,
            "Enhanced App Intents (Siri 2.0)",
            "Enable the App Intents v2 runtime for richer third-party Siri actions."))
        layout.addWidget(_ff(TweakID.Siri2LiveTranslation,
            "Siri Live Call Translation",
            "Enable real-time spoken translation during phone and FaceTime calls."))

        # ── iOS 27 Home Screen ────────────────────────────────────────────────
        layout.addWidget(_section_label("iOS 27 Concept – Home Screen"))
        layout.addWidget(_divider())
        layout.addWidget(_ff(TweakID.iOS27LargeWidgets,
            "iOS 27 XL Widget Sizes",
            "Unlock extra-large widget slots on the home screen grid."))
        layout.addWidget(_ff(TweakID.iOS27HomeScreenRedesign,
            "iOS 27 Home Screen Grid",
            "Enable the redesigned adaptive icon grid layout introduced in iOS 27."))
        layout.addWidget(_ff(TweakID.iOS27AppLibraryRedesign,
            "iOS 27 App Library Redesign",
            "Enable the new categorised App Library with Liquid Glass cards."))
        layout.addWidget(_ff(TweakID.iOS27ContextMenuRedesign,
            "iOS 27 Context Menu Redesign",
            "Use the new full-width context menus with Liquid Glass background."))
        layout.addWidget(_ff(TweakID.iOS27AppSwitcherRedesign,
            "iOS 27 App Switcher",
            "Enable the carousel-style app switcher with glass cards."))

        # ── iOS 27 System UI ──────────────────────────────────────────────────
        layout.addWidget(_section_label("iOS 27 Concept – System UI"))
        layout.addWidget(_divider())
        layout.addWidget(_ff(TweakID.iOS27CCRedesign,
            "iOS 27 Control Centre Redesign",
            "Switch to the new modular, resizable Control Centre from iOS 27."))
        layout.addWidget(_ff(TweakID.iOS27NotificationsRedesign,
            "iOS 27 Notifications Redesign",
            "Enable grouped, stacked notification cards with Liquid Glass styling."))
        layout.addWidget(_ff(TweakID.iOS27LockScreenRedesign,
            "iOS 27 Lock Screen Redesign",
            "Enable the next-generation lock screen with depth-effect clock and glassy widgets."))
        layout.addWidget(_ff(TweakID.iOS27StatusBarRedesign,
            "iOS 27 Status Bar Redesign",
            "Use the condensed, always-glassy status bar style from iOS 27."))
        layout.addWidget(_ff(TweakID.iOS27ShareSheetRedesign,
            "iOS 27 Share Sheet Redesign",
            "Enable the new compact Share Sheet with Liquid Glass surface."))

        # ── iOS 27 Typography & Fonts ─────────────────────────────────────────
        layout.addWidget(_section_label("iOS 27 Concept – Typography & Fonts"))
        layout.addWidget(_divider())
        layout.addWidget(_ff(TweakID.iOS27DynamicType2,
            "Dynamic Type v2",
            "Enable the iOS 27 Dynamic Type engine with more granular size steps."))
        layout.addWidget(_ff(TweakID.iOS27NewSystemFont,
            "iOS 27 New System Font",
            "Switch to the new variable-weight system font introduced in iOS 27."))
        layout.addWidget(_ff(TweakID.iOS27BoldUIElements,
            "Bold UI Elements",
            "Apply heavier font weights to buttons, labels, and navigation bars system-wide."))
        layout.addWidget(_ff(TweakID.iOS27LargeHeaderStyle,
            "Large Navigation Headers",
            "Use the iOS 27 oversized header style in all navigation controllers."))
        layout.addWidget(_ff(TweakID.iOS27CompactLabels,
            "Compact Label Layout",
            "Use tighter line-height and letter-spacing in system labels for a denser UI."))

        # ── iOS 27 Animations ─────────────────────────────────────────────────
        layout.addWidget(_section_label("iOS 27 Concept – Animations"))
        layout.addWidget(_divider())
        layout.addWidget(_ff(TweakID.iOS27SpringAnimations,
            "Spring Animation Curves v2",
            "Use the iOS 27 refined spring physics for all UIKit push/pop transitions."))
        layout.addWidget(_ff(TweakID.iOS27MorphTransitions,
            "Morph App Transitions",
            "App icons morph fluidly into app content when launching and closing apps."))
        layout.addWidget(_ff(TweakID.iOS27ElasticBounce,
            "Elastic Bounce Scrolling",
            "Adds exaggerated elastic overscroll physics to all scroll views."))
        layout.addWidget(_ff(TweakID.iOS27ZoomTransitions,
            "App Zoom Transitions v2",
            "Enable the improved zoom-in/zoom-out app launch animation from iOS 27."))
        layout.addWidget(_ff(TweakID.iOS27GlassReveal,
            "Glass Reveal Sheet Animations",
            "Sheets and panels animate in with a frosted-glass reveal effect."))
        layout.addWidget(_ff(TweakID.iOS27ReducedMotionAlt,
            "Reduced Motion Alternative",
            "Use the iOS 27 cross-fade alternative for Reduce Motion instead of dissolves."))

        # ── iOS 27 Colors & Appearance ────────────────────────────────────────
        layout.addWidget(_section_label("iOS 27 Concept – Colors & Appearance"))
        layout.addWidget(_divider())
        layout.addWidget(_ff(TweakID.iOS27VividColors,
            "Vivid Color Palette",
            "Enable the iOS 27 high-saturation vivid color palette system-wide."))
        layout.addWidget(_ff(TweakID.iOS27DynamicColors,
            "Dynamic Wallpaper Color Extraction",
            "Tint system chrome with colors sampled from the current wallpaper."))
        layout.addWidget(_ff(TweakID.iOS27TintEverywhere,
            "Global Accent Tint Propagation",
            "Propagate your chosen accent tint to every system UI element."))
        layout.addWidget(_ff(TweakID.iOS27TrueBlack,
            "True Black Dark Mode",
            "Force OLED true-black backgrounds in dark mode across all apps."))
        layout.addWidget(_ff(TweakID.iOS27ColorizedGlass,
            "Colorized Liquid Glass",
            "Liquid Glass surfaces inherit the local accent tint for a colorized look."))
        layout.addWidget(_ff(TweakID.iOS27MaterialVariant2,
            "Glass Material Variant 2",
            "Use the denser, more opaque Liquid Glass material variant from iOS 27 beta."))

        # ── iOS 27 Keyboard ───────────────────────────────────────────────────
        layout.addWidget(_section_label("iOS 27 Concept – Keyboard"))
        layout.addWidget(_divider())
        layout.addWidget(_ff(TweakID.iOS27KeyboardRedesign,
            "iOS 27 Keyboard Redesign",
            "Enable the taller, wider key layout with Liquid Glass key caps."))
        layout.addWidget(_ff(TweakID.iOS27KeyboardGlass,
            "Glass Keyboard Background",
            "Apply a translucent Liquid Glass surface behind the keyboard."))
        layout.addWidget(_ff(TweakID.iOS27SmartPrediction,
            "Enhanced Predictive Input Bar",
            "Use the iOS 27 wider prediction bar with inline completions and emoji hints."))
        layout.addWidget(_ff(TweakID.iOS27KeyboardHaptics,
            "Per-Key Haptic Feedback",
            "Enable distinct haptic click per key press (requires supported hardware)."))

        # ── iOS 27 Multitasking ───────────────────────────────────────────────
        layout.addWidget(_section_label("iOS 27 Concept – Multitasking"))
        layout.addWidget(_divider())
        layout.addWidget(_ff(TweakID.iOS27StagedMultitasking,
            "Enhanced Stage Manager",
            "Enable the iOS 27 Stage Manager with gesture-based window snapping on iPhone."))
        layout.addWidget(_ff(TweakID.iOS27FloatingApps,
            "Floating App Windows",
            "Run a secondary app in a floating, resizable window over the home screen."))
        layout.addWidget(_ff(TweakID.iOS27PiPEnhancements,
            "Picture-in-Picture Enhancements",
            "Enable the iOS 27 PiP with corner snapping, zoom controls, and glass frame."))
        layout.addWidget(_ff(TweakID.iOS27SplitViewIPhone,
            "Split View on iPhone (Large Models)",
            "Enable two-app Split View on iPhone 16 Plus / Pro Max and larger."))

        # ── iOS 27 Photos & Camera ────────────────────────────────────────────
        layout.addWidget(_section_label("iOS 27 Concept – Photos & Camera"))
        layout.addWidget(_divider())
        layout.addWidget(_ff(TweakID.iOS27PhotosRedesign,
            "Photos App Redesign",
            "Enable the iOS 27 Photos app with glass category cards and adaptive layout."))
        layout.addWidget(_ff(TweakID.iOS27CameraRedesign,
            "Camera App Redesign",
            "Enable the iOS 27 Camera UI with floating glass controls and new shutter."))
        layout.addWidget(_ff(TweakID.iOS27SmartAlbums2,
            "Smart Albums v2",
            "Enable machine-learning smart albums powered by the iOS 27 neural engine."))
        layout.addWidget(_ff(TweakID.iOS27CinematicCapture,
            "Enhanced Cinematic Mode",
            "Enable iOS 27 Cinematic Mode with improved depth transitions and AI subject lock."))
        layout.addWidget(_ff(TweakID.iOS27ProRAWEnhanced,
            "Enhanced ProRAW Processing",
            "Enable the iOS 27 ProRAW pipeline with wider tone-mapping and LUT support."))

        # ── iOS 27 Privacy & Security ─────────────────────────────────────────
        layout.addWidget(_section_label("iOS 27 Concept – Privacy & Security"))
        layout.addWidget(_divider())
        layout.addWidget(_ff(TweakID.iOS27PrivacyDashboard2,
            "Privacy Dashboard v2",
            "Enable the redesigned Privacy Dashboard with timeline and app usage heat map."))
        layout.addWidget(_ff(TweakID.iOS27AppPrivacyReport2,
            "Detailed App Privacy Report",
            "Show per-permission network access logs and sensor usage in App Privacy Report."))
        layout.addWidget(_ff(TweakID.iOS27BiometricEnhanced,
            "Enhanced Biometric Auth",
            "Enable iOS 27 Face ID velocity matching and continuous authentication mode."))
        layout.addWidget(_ff(TweakID.iOS27LockdownModeLite,
            "Lockdown Mode Lite",
            "A lighter Lockdown Mode that restricts high-risk attack surfaces without "
            "fully disabling web browsing."))

        # ── Liquid Glass 2.0 per-app ──────────────────────────────────────────
        layout.addWidget(_section_label("Liquid Glass 2.0 – Per-App Extensions"))
        layout.addWidget(_divider())
        layout.addWidget(_ff(TweakID.SolariumFFMessages,
            "Liquid Glass in Messages",
            "Apply Solarium Liquid Glass rendering to the Messages app UI."))
        layout.addWidget(_ff(TweakID.SolariumFFMaps,
            "Liquid Glass in Maps",
            "Apply Solarium Liquid Glass to Maps cards, sheets, and overlays."))
        layout.addWidget(_ff(TweakID.SolariumFFSafari,
            "Liquid Glass in Safari",
            "Apply Solarium rendering to Safari toolbars and overlay panels."))
        layout.addWidget(_ff(TweakID.SolariumFFSpotlight,
            "Liquid Glass in Spotlight",
            "Apply Solarium Liquid Glass to the Spotlight search interface."))
        layout.addWidget(_ff(TweakID.SolariumFFControlCenter,
            "Liquid Glass in Control Centre",
            "Apply Solarium rendering to Control Centre modules and panels."))
        layout.addWidget(_ff(TweakID.SolariumFFNotifications,
            "Liquid Glass Notification Banners",
            "Apply Solarium Liquid Glass to notification banners and sheets."))
        layout.addWidget(_ff(TweakID.SolariumFFWidgets,
            "Liquid Glass Widgets",
            "Apply Solarium Liquid Glass background to home screen widgets."))

        # ── Liquid Glass 3.0 – more apps ─────────────────────────────────────
        layout.addWidget(_section_label("Liquid Glass 3.0 – More App Extensions"))
        layout.addWidget(_divider())
        layout.addWidget(_ff(TweakID.SolariumFFMusic,
            "Liquid Glass in Music",
            "Apply Solarium rendering to the Music app player and library UI."))
        layout.addWidget(_ff(TweakID.SolariumFFPodcasts,
            "Liquid Glass in Podcasts",
            "Apply Solarium rendering to the Podcasts player and episode list."))
        layout.addWidget(_ff(TweakID.SolariumFFPhone,
            "Liquid Glass in Phone",
            "Apply Solarium Liquid Glass to the Phone dialer and call screens."))
        layout.addWidget(_ff(TweakID.SolariumFFCalendar,
            "Liquid Glass in Calendar",
            "Apply Solarium rendering to Calendar event cards and day/month views."))
        layout.addWidget(_ff(TweakID.SolariumFFReminders,
            "Liquid Glass in Reminders",
            "Apply Solarium rendering to Reminders list rows and detail sheets."))
        layout.addWidget(_ff(TweakID.SolariumFFNotes,
            "Liquid Glass in Notes",
            "Apply Solarium rendering to the Notes toolbar and formatting panel."))

        # ── Liquid Glass Fine-Tuning ───────────────────────────────────────────
        layout.addWidget(_section_label("Liquid Glass – Fine-Tuning"))
        layout.addWidget(_divider())
        layout.addWidget(_ff(TweakID.NoLiquidStatusBar,
            "Disable Glass on Status Bar",
            "Remove the specular / glass material from the status bar."))
        layout.addWidget(_ff(TweakID.NoLiquidNotifications,
            "Disable Glass on Notifications",
            "Use solid surfaces instead of Liquid Glass for notification banners."))
        layout.addWidget(_ff(TweakID.SolariumHighContrast,
            "High Contrast Liquid Glass",
            "Increase contrast of glass layers for better legibility."))
        layout.addWidget(_ff(TweakID.SolariumForceLightTint,
            "Force Light Tint on Glass",
            "Always render Liquid Glass with a light tint regardless of appearance mode."))
        layout.addWidget(_ff(TweakID.SolariumMaxBlur,
            "Maximum Blur Radius",
            "Push blur radius of Liquid Glass surfaces to the maximum supported value."))

        # ── SpringBoard iOS 27 Core ───────────────────────────────────────────
        layout.addWidget(_section_label("SpringBoard – iOS 27 Options"))
        layout.addWidget(_divider())
        layout.addWidget(_ff(TweakID.SBAlwaysGlassHeaders,
            "Always Show Glass Section Headers",
            "Keep home screen section labels visible with glass backgrounds at all times."))
        layout.addWidget(_ff(TweakID.SBExpandedDynamicIsland,
            "Expanded Dynamic Island",
            "Enable expanded Dynamic Island interactions and persistent content glyphs."))
        layout.addWidget(_ff(TweakID.SBShowWeatherLockScreen,
            "Live Weather on Lock Screen",
            "Show animated live weather data directly on the lock screen background."))
        layout.addWidget(_ff(TweakID.SBEnhancedHaptics,
            "Enhanced System Haptics",
            "Enable richer haptic feedback patterns for SpringBoard interactions."))
        layout.addWidget(_ff(TweakID.SBShowBatteryPercentageAlways,
            "Always Show Battery Percentage",
            "Force the battery percentage to appear in the status bar at all times."))
        layout.addWidget(_ff(TweakID.SBHideHomeIndicator,
            "Hide Home Bar Indicator",
            "Hide the home indicator bar at the bottom of the screen."))
        layout.addWidget(_ff(TweakID.SBDisableParallaxEffect,
            "Disable Parallax / Motion Effect",
            "Disable the parallax depth effect on home screen icons and wallpaper."))

        # ── SpringBoard iOS 27 Advanced ───────────────────────────────────────
        layout.addWidget(_section_label("SpringBoard – iOS 27 Advanced"))
        layout.addWidget(_divider())
        layout.addWidget(_ff(TweakID.SBSmartStackRedesign,
            "Smart Stack Redesign",
            "Enable the iOS 27 Smart Stack with horizontal swipe and AI ordering."))
        layout.addWidget(_ff(TweakID.SBIconBadgeRedesign,
            "Icon Badge Redesign",
            "Use the iOS 27 pill-shaped count badges instead of circular ones."))
        layout.addWidget(_ff(TweakID.SBTransparentFolders,
            "Glass / Transparent Folders",
            "Render app folders with a Liquid Glass translucent background."))
        layout.addWidget(_ff(TweakID.SBAlwaysShowClockDI,
            "Always Show Clock with Dynamic Island",
            "Keep the time visible in the corner even when Dynamic Island is expanded."))
        layout.addWidget(_ff(TweakID.SBFocusFiltersRedesign,
            "Focus Filters iOS 27 Redesign",
            "Enable the redesigned Focus filter UI with per-app tint and glass overlays."))

    def load_page(self):
        load_ios27()
