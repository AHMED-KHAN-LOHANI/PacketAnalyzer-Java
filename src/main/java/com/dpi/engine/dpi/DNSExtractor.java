package com.dpi.engine.dpi;

/**
 * Extracts queried domain names from DNS query packets.
 * Ported from the C++ DNSExtractor.
 */
public class DNSExtractor {

    /**
     * Check if this is a DNS query (not response).
     * QR bit (byte 2, bit 7) must be 0, QDCOUNT must be > 0.
     */
    public static boolean isDNSQuery(byte[] payload, int length) {
        if (length < 12) return false;

        // QR bit is the MSB of byte 2
        if ((payload[2] & 0x80) != 0) return false; // This is a response

        // QDCOUNT (bytes 4-5)
        int qdcount = ((payload[4] & 0xFF) << 8) | (payload[5] & 0xFF);
        if (qdcount == 0) return false;

        return true;
    }

    /**
     * Extract the first queried domain name from a DNS query.
     * @return the domain string (e.g. "www.google.com"), or null.
     */
    public static String extractQuery(byte[] payload, int length) {
        if (!isDNSQuery(payload, length)) return null;

        int offset = 12; // skip DNS header (12 bytes)
        StringBuilder domain = new StringBuilder();

        while (offset < length) {
            int labelLength = payload[offset] & 0xFF;

            if (labelLength == 0) break; // end of domain name

            if (labelLength > 63) break; // compression pointer or invalid

            offset++;
            if (offset + labelLength > length) break;

            if (domain.length() > 0) domain.append('.');
            domain.append(new String(payload, offset, labelLength));
            offset += labelLength;
        }

        return domain.length() == 0 ? null : domain.toString();
    }
}
