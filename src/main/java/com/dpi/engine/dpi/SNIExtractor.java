/*
 * Decompiled with CFR 0.152.
 */
package com.dpi.engine.dpi;

public class SNIExtractor {
    private static final int CONTENT_TYPE_HANDSHAKE = 22;
    private static final int HANDSHAKE_CLIENT_HELLO = 1;
    private static final int EXTENSION_SNI = 0;
    private static final int SNI_TYPE_HOSTNAME = 0;

    public static boolean isTLSClientHello(byte[] payload, int length) {
        if (length < 9) {
            return false;
        }
        if ((payload[0] & 0xFF) != 22) {
            return false;
        }
        int version = SNIExtractor.readUint16BE(payload, 1);
        if (version < 768 || version > 772) {
            return false;
        }
        int recordLength = SNIExtractor.readUint16BE(payload, 3);
        if (recordLength > length - 5) {
            return false;
        }
        return (payload[5] & 0xFF) == 1;
    }

    public static String extract(byte[] payload, int length) {
        int extensionsLength;
        int extensionsEnd;
        int compressionMethodsLength;
        int cipherSuitesLength;
        int sessionIdLength;
        if (!SNIExtractor.isTLSClientHello(payload, length)) {
            return null;
        }
        int offset = 5;
        offset += 4;
        if ((offset += 34) >= length) {
            return null;
        }
        if ((offset += 1 + (sessionIdLength = payload[offset] & 0xFF)) + 2 > length) {
            return null;
        }
        if ((offset += 2 + (cipherSuitesLength = SNIExtractor.readUint16BE(payload, offset))) >= length) {
            return null;
        }
        if ((offset += 1 + (compressionMethodsLength = payload[offset] & 0xFF)) + 2 > length) {
            return null;
        }
        if ((extensionsEnd = (offset += 2) + (extensionsLength = SNIExtractor.readUint16BE(payload, offset))) > length) {
            extensionsEnd = length;
        }
        while (offset + 4 <= extensionsEnd) {
            int extensionLength;
            int extensionType = SNIExtractor.readUint16BE(payload, offset);
            if ((offset += 4) + (extensionLength = SNIExtractor.readUint16BE(payload, offset + 2)) > extensionsEnd) break;
            if (extensionType == 0) {
                int sniListLength;
                if (extensionLength < 5 || (sniListLength = SNIExtractor.readUint16BE(payload, offset)) < 3) break;
                int sniType = payload[offset + 2] & 0xFF;
                int sniLength = SNIExtractor.readUint16BE(payload, offset + 3);
                if (sniType != 0 || sniLength > extensionLength - 5) break;
                return new String(payload, offset + 5, sniLength);
            }
            offset += extensionLength;
        }
        return null;
    }

    private static int readUint16BE(byte[] data, int offset) {
        return (data[offset] & 0xFF) << 8 | data[offset + 1] & 0xFF;
    }
}

