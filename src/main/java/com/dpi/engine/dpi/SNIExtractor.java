package com.dpi.engine.dpi;

public class SNIExtractor {
    private static final int CONTENT_TYPE_HANDSHAKE = 22;
    private static final int HANDSHAKE_CLIENT_HELLO = 1;
    private static final int EXTENSION_SNI = 0;
    private static final int SNI_TYPE_HOSTNAME = 0;

    public static boolean isTLSClientHello(byte[] payload, int length) {
        if (length < 9) return false;
        if ((payload[0] & 0xFF) != 22) return false;
        int version = readUint16BE(payload, 1);
        if (version < 768 || version > 772) return false;
        int recordLength = readUint16BE(payload, 3);
        if (recordLength > length - 5) return false;
        return (payload[5] & 0xFF) == 1;
    }

    public static String extract(byte[] payload, int length) {
        if (!isTLSClientHello(payload, length)) return null;
        int offset = 5;
        offset += 4; // skip handshake header
        if (offset + 34 >= length) return null;
        offset += 34; // skip client version and random
        if (offset >= length) return null;
        int sessionIdLength = payload[offset] & 0xFF;
        offset += 1 + sessionIdLength;
        if (offset + 2 > length) return null;
        int cipherSuitesLength = readUint16BE(payload, offset);
        offset += 2 + cipherSuitesLength;
        if (offset >= length) return null;
        int compressionMethodsLength = payload[offset] & 0xFF;
        offset += 1 + compressionMethodsLength;
        if (offset + 2 > length) return null;
        int extensionsLength = readUint16BE(payload, offset);
        offset += 2;
        int extensionsEnd = offset + extensionsLength;
        if (extensionsEnd > length) extensionsEnd = length;

        while (offset + 4 <= extensionsEnd) {
            int extensionType = readUint16BE(payload, offset);
            int extensionLength = readUint16BE(payload, offset + 2);
            offset += 4;

            if (offset + extensionLength > extensionsEnd) break;

            if (extensionType == 0) { // SNI
                if (extensionLength < 5) break;
                int sniListLength = readUint16BE(payload, offset);
                if (sniListLength < 3) break;
                int sniType = payload[offset + 2] & 0xFF;
                int sniLength = readUint16BE(payload, offset + 3);
                if (sniType == 0 && sniLength <= extensionLength - 5) {
                    return new String(payload, offset + 5, sniLength);
                }
                break;
            }
            offset += extensionLength;
        }
        return null;
    }

    private static int readUint16BE(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }
}
