package com.dpi.engine.dpi;

/**
 * Extracts the Host header from plain-text HTTP requests.
 * Ported from the C++ HTTPHostExtractor.
 */
public class HTTPHostExtractor {

    private static final String[] HTTP_METHODS = {
        "GET ", "POST", "PUT ", "HEAD", "DELE", "PATC", "OPTI"
    };

    /**
     * Check if the payload starts with an HTTP method.
     */
    public static boolean isHTTPRequest(byte[] payload, int length) {
        if (length < 4) return false;
        for (String method : HTTP_METHODS) {
            boolean match = true;
            byte[] methodBytes = method.getBytes();
            for (int i = 0; i < 4; i++) {
                if ((payload[i] & 0xFF) != (methodBytes[i] & 0xFF)) {
                    match = false;
                    break;
                }
            }
            if (match) return true;
        }
        return false;
    }

    /**
     * Extract the Host header value from an HTTP request payload.
     * @return the host (with port stripped), or null.
     */
    public static String extract(byte[] payload, int length) {
        if (!isHTTPRequest(payload, length)) return null;

        // Search for "Host: " header (case-insensitive)
        for (int i = 0; i + 6 < length; i++) {
            if ((payload[i] == 'H' || payload[i] == 'h') &&
                (payload[i+1] == 'o' || payload[i+1] == 'O') &&
                (payload[i+2] == 's' || payload[i+2] == 'S') &&
                (payload[i+3] == 't' || payload[i+3] == 'T') &&
                payload[i+4] == ':') {

                // Skip "Host:" and whitespace
                int start = i + 5;
                while (start < length && (payload[start] == ' ' || payload[start] == '\t')) {
                    start++;
                }

                // Find end of line
                int end = start;
                while (end < length && payload[end] != '\r' && payload[end] != '\n') {
                    end++;
                }

                if (end > start) {
                    String host = new String(payload, start, end - start);
                    // Remove port if present
                    int colonPos = host.indexOf(':');
                    if (colonPos != -1) {
                        host = host.substring(0, colonPos);
                    }
                    return host;
                }
            }
        }
        return null;
    }
}
