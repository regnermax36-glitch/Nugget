from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QScrollArea,
    QFrame, QSizePolicy, QSpacerItem
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont

from ..page import Page
from src.tweaks.tweak_loader import load_safari_net
from src.tweaks.tweaks import TweakID


class SafariNetPage(Page, QWidget):
    """Real com.apple.mobilesafari managed-preference keys.
    Applied via sparserestore — no BookRestore required."""

    def __init__(self):
        Page.__init__(self)
        QWidget.__init__(self)
        self._setup_ui()

    def _setup_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        outer.addWidget(scroll)

        container = QWidget()
        self.layout_main = QVBoxLayout(container)
        self.layout_main.setContentsMargins(30, 20, 30, 20)
        self.layout_main.setSpacing(12)
        scroll.setWidget(container)

        title_font = QFont()
        title_font.setPointSize(18)
        title_font.setBold(True)
        section_font = QFont()
        section_font.setPointSize(11)
        section_font.setBold(True)

        title = QLabel("Safari & Networking")
        title.setFont(title_font)
        self.layout_main.addWidget(title)

        subtitle = QLabel(
            "Real com.apple.mobilesafari managed-preference keys read by "
            "MobileSafari and WebKit at launch. Applied via sparserestore — "
            "the original method, no BookRestore."
        )
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet("color: #aaaaaa; font-size: 13px;")
        self.layout_main.addWidget(subtitle)

        # ── Developer ─────────────────────────────────────────────────────────
        self._add_divider()
        self._section("Developer & Debugging", section_font)

        self.webInspectorBtns = self._add_row(
            "Web Inspector",
            "WebKitDeveloperExtrasEnabled — enables the Web Inspector / remote "
            "debugger that Xcode connects to when you choose Develop → device in Safari."
        )

        # ── Privacy & Security ─────────────────────────────────────────────────
        self._add_divider()
        self._section("Privacy & Security", section_font)

        self.doNotTrackBtns = self._add_row(
            "Do Not Track Header",
            "DNTEnabled — sends the DNT:1 request header with every HTTP/HTTPS "
            "request, signalling ad trackers to opt out of cross-site tracking."
        )
        self.fraudWarningBtns = self._add_row(
            "Fraudulent-Site Warning",
            "WarnAboutFraudulentWebsites — shows a full-screen phishing warning "
            "when Google Safe Browsing flags a URL as malicious."
        )
        self.privateRelayBtns = self._add_row(
            "iCloud Private Relay",
            "iCloudPrivateRelayEnabled — routes Safari traffic through Apple's "
            "two-hop relay network so no single party sees both your IP and your "
            "browsing destination."
        )
        self.echBtns = self._add_row(
            "Encrypted Client Hello (ECH)",
            "WebKitEncryptedClientHelloEnabled — encrypts the TLS 1.3 client-hello "
            "SNI field so network observers can't see which hostname you're connecting to."
        )

        # ── Content Controls ──────────────────────────────────────────────────
        self._add_divider()
        self._section("Content Controls", section_font)

        self.blockPopupsBtns = self._add_row(
            "Block Pop-ups",
            "BlockPopups — prevents websites from opening new windows or tabs "
            "without a user gesture (Apple MDM-documented key)."
        )
        self.allowHTTPBtns = self._add_row(
            "Allow Plain HTTP",
            "AllowHTTP — permits navigation to http:// URLs without automatic "
            "HTTPS upgrade. Useful for local dev servers and legacy intranets."
        )
        self.javaScriptBtns = self._add_row(
            "JavaScript Engine",
            "WebKitJavaScriptEnabled — master toggle for the JavaScriptCore engine. "
            "Disabling breaks most modern sites but reduces attack surface "
            "(Apple MDM restriction key)."
        )
        self.searchSuggestBtns = self._add_row(
            "Suppress Search Suggestions",
            "SuppressSearchSuggestions — stops Safari from sending partially typed "
            "queries to the search engine while you type."
        )
        self.fullURLBtns = self._add_row(
            "Show Full URL",
            "ShowFullURL — always displays the complete URL including scheme "
            "(https://) and path in the smart search bar."
        )

        # ── Modern Networking Protocols ────────────────────────────────────────
        self._add_divider()
        self._section("Modern Networking Protocols", section_font)

        self.http3Btns = self._add_row(
            "HTTP/3 (QUIC)",
            "WebKitNetworkHTTP3Enabled — allows the WebKit network process to "
            "negotiate HTTP/3 over QUIC (UDP-based) with supporting servers, "
            "reducing connection latency and improving stream multiplexing."
        )
        self.dohBtns = self._add_row(
            "DNS-over-HTTPS (DoH)",
            "WebKitDNSOverHTTPSEnabled — resolves DNS queries over an encrypted "
            "HTTPS channel, preventing ISP-level DNS snooping and spoofing."
        )

        self.layout_main.addItem(
            QSpacerItem(20, 20, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)
        )

    def _section(self, text: str, font: QFont):
        lbl = QLabel(text)
        lbl.setFont(font)
        lbl.setStyleSheet("color: #e8e8e8; margin-top: 6px;")
        self.layout_main.addWidget(lbl)

    def _add_divider(self):
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setStyleSheet("QFrame { color: #414141; }")
        self.layout_main.addWidget(line)

    def _add_row(self, label_text: str, description: str) -> QHBoxLayout:
        row_widget = QWidget()
        row_layout = QHBoxLayout(row_widget)
        row_layout.setContentsMargins(0, 2, 0, 2)
        row_layout.setSpacing(12)

        info = QWidget()
        info_layout = QVBoxLayout(info)
        info_layout.setContentsMargins(0, 0, 0, 0)
        info_layout.setSpacing(2)
        name_lbl = QLabel(label_text)
        name_lbl.setStyleSheet("font-size: 14px;")
        desc_lbl = QLabel(description)
        desc_lbl.setStyleSheet("font-size: 11px; color: #888888;")
        desc_lbl.setWordWrap(True)
        info_layout.addWidget(name_lbl)
        info_layout.addWidget(desc_lbl)
        info.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        row_layout.addWidget(info)

        btn_container = QWidget()
        btn_layout = QHBoxLayout(btn_container)
        btn_layout.setContentsMargins(0, 0, 0, 0)
        btn_layout.setSpacing(0)
        row_layout.addWidget(btn_container)

        self.layout_main.addWidget(row_widget)
        return btn_layout

    def load_page(self):
        load_safari_net()
        self.createRadioBtns(TweakID.SafariWebInspector, self.webInspectorBtns)
        self.createRadioBtns(TweakID.SafariDoNotTrack, self.doNotTrackBtns)
        self.createRadioBtns(TweakID.SafariFraudWarning, self.fraudWarningBtns)
        self.createRadioBtns(TweakID.SafariPrivateRelay, self.privateRelayBtns)
        self.createRadioBtns(TweakID.SafariECH, self.echBtns)
        self.createRadioBtns(TweakID.SafariBlockPopups, self.blockPopupsBtns)
        self.createRadioBtns(TweakID.SafariAllowHTTP, self.allowHTTPBtns)
        self.createRadioBtns(TweakID.SafariJavaScript, self.javaScriptBtns)
        self.createRadioBtns(TweakID.SafariSearchSuggest, self.searchSuggestBtns)
        self.createRadioBtns(TweakID.SafariFullURL, self.fullURLBtns)
        self.createRadioBtns(TweakID.SafariHTTP3, self.http3Btns)
        self.createRadioBtns(TweakID.SafariDoH, self.dohBtns)
