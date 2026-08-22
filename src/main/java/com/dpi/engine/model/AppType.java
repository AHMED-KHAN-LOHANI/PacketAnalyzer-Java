package com.dpi.engine.model;

/**
 * Application classification types - mirrors the C++ AppType enum exactly.
 */
public enum AppType {
    UNKNOWN("Unknown"),
    HTTP("HTTP"),
    HTTPS("HTTPS"),
    DNS("DNS"),
    TLS("TLS"),
    QUIC("QUIC"),
    GOOGLE("Google"),
    FACEBOOK("Facebook"),
    YOUTUBE("YouTube"),
    TWITTER("Twitter/X"),
    INSTAGRAM("Instagram"),
    NETFLIX("Netflix"),
    AMAZON("Amazon"),
    MICROSOFT("Microsoft"),
    APPLE("Apple"),
    WHATSAPP("WhatsApp"),
    TELEGRAM("Telegram"),
    TIKTOK("TikTok"),
    SPOTIFY("Spotify"),
    ZOOM("Zoom"),
    DISCORD("Discord"),
    GITHUB("GitHub"),
    CLOUDFLARE("Cloudflare");

    private final String displayName;

    AppType(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() { return displayName; }

    /** Look up an AppType by its display name (case-sensitive match). */
    public static AppType fromDisplayName(String name) {
        for (AppType at : values()) {
            if (at.displayName.equals(name)) return at;
        }
        return null;
    }

    /**
     * Map an SNI / domain string to an application type.
     * Ported from C++ sniToAppType().
     */
    public static AppType fromSNI(String sni) {
        if (sni == null || sni.isEmpty()) return UNKNOWN;
        String lower = sni.toLowerCase();

        // Google (including gstatic, googleapis, ggpht, gvt1)
        if (lower.contains("google") || lower.contains("gstatic")
                || lower.contains("googleapis") || lower.contains("ggpht")
                || lower.contains("gvt1")) {
            return GOOGLE;
        }

        // YouTube (must be checked BEFORE Google since it's more specific)
        if (lower.contains("youtube") || lower.contains("ytimg")
                || lower.contains("youtu.be") || lower.contains("yt3.ggpht")) {
            return YOUTUBE;
        }

        // Facebook / Meta
        if (lower.contains("facebook") || lower.contains("fbcdn")
                || lower.contains("fb.com") || lower.contains("fbsbx")
                || lower.contains("meta.com")) {
            return FACEBOOK;
        }

        // Instagram
        if (lower.contains("instagram") || lower.contains("cdninstagram")) {
            return INSTAGRAM;
        }

        // WhatsApp
        if (lower.contains("whatsapp") || lower.contains("wa.me")) {
            return WHATSAPP;
        }

        // Twitter / X
        if (lower.contains("twitter") || lower.contains("twimg")
                || lower.equals("x.com") || lower.startsWith("x.com")
                || lower.contains(".x.com")
                || lower.equals("t.co") || lower.startsWith("t.co")
                || lower.contains(".t.co")) {
            return TWITTER;
        }

        // Netflix
        if (lower.contains("netflix") || lower.contains("nflxvideo")
                || lower.contains("nflximg")) {
            return NETFLIX;
        }

        // Amazon
        if (lower.contains("amazon") || lower.contains("amazonaws")
                || lower.contains("cloudfront") || lower.contains("aws")) {
            return AMAZON;
        }

        // Microsoft
        if (lower.contains("microsoft") || lower.contains("msn.com")
                || lower.contains("office") || lower.contains("azure")
                || lower.contains("live.com") || lower.contains("outlook")
                || lower.contains("bing")) {
            return MICROSOFT;
        }

        // Apple
        if (lower.contains("apple") || lower.contains("icloud")
                || lower.contains("mzstatic") || lower.contains("itunes")) {
            return APPLE;
        }

        // Telegram
        if (lower.contains("telegram") || lower.contains("t.me")) {
            return TELEGRAM;
        }

        // TikTok
        if (lower.contains("tiktok") || lower.contains("tiktokcdn")
                || lower.contains("musical.ly") || lower.contains("bytedance")) {
            return TIKTOK;
        }

        // Spotify
        if (lower.contains("spotify") || lower.contains("scdn.co")) {
            return SPOTIFY;
        }

        // Zoom
        if (lower.contains("zoom")) {
            return ZOOM;
        }

        // Discord
        if (lower.contains("discord") || lower.contains("discordapp")) {
            return DISCORD;
        }

        // GitHub
        if (lower.contains("github") || lower.contains("githubusercontent")) {
            return GITHUB;
        }

        // Cloudflare
        if (lower.contains("cloudflare") || lower.contains("cf-")) {
            return CLOUDFLARE;
        }

        // SNI is present but not recognized -> mark as generic HTTPS
        return HTTPS;
    }
}
