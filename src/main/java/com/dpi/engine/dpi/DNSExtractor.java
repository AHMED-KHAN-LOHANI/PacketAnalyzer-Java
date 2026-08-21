/*
 * Decompiled with CFR 0.152.
 */
package com.dpi.engine.dpi;

public class DNSExtractor {
    public static boolean isDNSQuery(byte[] payload, int length) {
        if (length < 12) {
            return false;
        }
        if ((payload[2] & 0x80) != 0) {
            return false;
        }
        int qdcount = (payload[4] & 0xFF) << 8 | payload[5] & 0xFF;
        return qdcount != 0;
    }

    public static String extractQuery(byte[] payload, int length) {
        int labelLength;
        if (!DNSExtractor.isDNSQuery(payload, length)) {
            return null;
        }
        StringBuilder domain = new StringBuilder();
        for (int offset = 12; offset < length && (labelLength = payload[offset] & 0xFF) != 0 && labelLength <= 63 && ++offset + labelLength <= length; offset += labelLength) {
            if (domain.length() > 0) {
                domain.append('.');
            }
            domain.append(new String(payload, offset, labelLength));
        }
        return domain.length() == 0 ? null : domain.toString();
    }
}

