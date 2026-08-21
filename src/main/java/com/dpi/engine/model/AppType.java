/*
 * Decompiled with CFR 0.152.
 */
package com.dpi.engine.model;

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

    private AppType(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return this.displayName;
    }

    public static AppType fromDisplayName(String name) {
        for (AppType at : AppType.values()) {
            if (!at.displayName.equals(name)) continue;
            return at;
        }
        return null;
    }

    public static AppType fromSNI(String sni) {
        if (sni == null || sni.isEmpty()) {
            return UNKNOWN;
        }
        String lower = sni.toLowerCase();
        if (lower.contains("google") || lower.contains("gstatic") || lower.contains("googleapis") || lower.contains("ggpht") || lower.contains("gvt1")) {
            return GOOGLE;
        }
        if (lower.contains("youtube") || lower.contains("ytimg") || lower.contains("youtu.be") || lower.contains("yt3.ggpht")) {
            return YOUTUBE;
        }
        if (lower.contains("facebook") || lower.contains("fbcdn") || lower.contains("fb.com") || lower.contains("fbsbx") || lower.contains("meta.com")) {
            return FACEBOOK;
        }
        if (lower.contains("instagram") || lower.contains("cdninstagram")) {
            return INSTAGRAM;
        }
        if (lower.contains("whatsapp") || lower.contains("wa.me")) {
            return WHATSAPP;
        }
        if (lower.contains("twitter") || lower.contains("twimg") || lower.equals("x.com") || lower.startsWith("x.com") || lower.contains(".x.com") || lower.equals("t.co") || lower.startsWith("t.co") || lower.contains(".t.co")) {
            return TWITTER;
        }
        if (lower.contains("netflix") || lower.contains("nflxvideo") || lower.contains("nflximg")) {
            return NETFLIX;
        }
        if (lower.contains("amazon") || lower.contains("amazonaws") || lower.contains("cloudfront") || lower.contains("aws")) {
            return AMAZON;
        }
        if (lower.contains("microsoft") || lower.contains("msn.com") || lower.contains("office") || lower.contains("azure") || lower.contains("live.com") || lower.contains("outlook") || lower.contains("bing")) {
            return MICROSOFT;
        }
        if (lower.contains("apple") || lower.contains("icloud") || lower.contains("mzstatic") || lower.contains("itunes")) {
            return APPLE;
        }
        if (lower.contains("telegram") || lower.contains("t.me")) {
            return TELEGRAM;
        }
        if (lower.contains("tiktok") || lower.contains("tiktokcdn") || lower.contains("musical.ly") || lower.contains("bytedance")) {
            return TIKTOK;
        }
        if (lower.contains("spotify") || lower.contains("scdn.co")) {
            return SPOTIFY;
        }
        if (lower.contains("zoom")) {
            return ZOOM;
        }
        if (lower.contains("discord") || lower.contains("discordapp")) {
            return DISCORD;
        }
        if (lower.contains("github") || lower.contains("githubusercontent")) {
            return GITHUB;
        }
        if (lower.contains("cloudflare") || lower.contains("cf-")) {
            return CLOUDFLARE;
        }
        return HTTPS;
    }
}

