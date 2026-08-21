/*
 * Decompiled with CFR 0.152.
 */
package com.dpi.engine.dpi;

public class HTTPHostExtractor {
    private static final String[] HTTP_METHODS = new String[]{"GET ", "POST", "PUT ", "HEAD", "DELE", "PATC", "OPTI"};

    public static boolean isHTTPRequest(byte[] payload, int length) {
        if (length < 4) {
            return false;
        }
        for (String method : HTTP_METHODS) {
            boolean match = true;
            byte[] methodBytes = method.getBytes();
            for (int i = 0; i < 4; ++i) {
                if ((payload[i] & 0xFF) == (methodBytes[i] & 0xFF)) continue;
                match = false;
                break;
            }
            if (!match) continue;
            return true;
        }
        return false;
    }

    public static String extract(byte[] payload, int length) {
        if (!HTTPHostExtractor.isHTTPRequest(payload, length)) {
            return null;
        }
        int i = 0;
        while (i + 6 < length) {
            if (!(payload[i] != 72 && payload[i] != 104 || payload[i + 1] != 111 && payload[i + 1] != 79 || payload[i + 2] != 115 && payload[i + 2] != 83 || payload[i + 3] != 116 && payload[i + 3] != 84 || payload[i + 4] != 58)) {
                int end;
                int start;
                for (start = i + 5; start < length && (payload[start] == 32 || payload[start] == 9); ++start) {
                }
                for (end = start; end < length && payload[end] != 13 && payload[end] != 10; ++end) {
                }
                if (end > start) {
                    String host = new String(payload, start, end - start);
                    int colonPos = host.indexOf(58);
                    if (colonPos != -1) {
                        host = host.substring(0, colonPos);
                    }
                    return host;
                }
            }
            ++i;
        }
        return null;
    }
}

