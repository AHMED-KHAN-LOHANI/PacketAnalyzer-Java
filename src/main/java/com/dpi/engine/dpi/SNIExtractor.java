package com.dpi.engine.dpi;

/**
 * Extracts the Server Name Indication (SNI) from a TLS Client Hello.
 * Ported line-for-line from the C++ SNIExtractor.
 *
 * TLS Client Hello structure:
 *   Record Layer:  ContentType(1) Version(2) Length(2)
 *   Handshake:    Type(1) Length(3) ClientVersion(2) Random(32)
 *                 SessionIDLen(1) SessionID(...) CipherSuitesLen(2) CipherSuites(...)
 *                 CompressionLen(1) Compression(...)
 *                 ExtensionsLen(2) Extensions(...)
 */
public class SNIExtractor {

    private static final int CONTENT_TYPE_HANDSHAKE = 0x16;
    private static final int HANDSHAKE_CLIENT_HELLO = 0x01;
    private static final int EXTENSION_SNI = 0x0000;
    private static final int SNI_TYPE_HOSTNAME = 0x00;

    /**
     * Check if the payload looks like a TLS Client Hello.
     */
    public static boolean isTLSClientHello(byte[] payload, int length) {
        if (length < 9) return false;

        if ((payload[0] & 0xFF) != CONTENT_TYPE_HANDSHAKE) return false;

        int version = readUint16BE(payload, 1);
        if (version < 0x0300 || version > 0x0304) return false;

        int recordLength = readUint16BE(payload, 3);
        if (recordLength > length - 5) return false;

        if ((payload[5] & 0xFF) != HANDSHAKE_CLIENT_HELLO) return false;

        return true;
    }

    /**
     * Extract the SNI hostname from a TLS Client Hello payload.
     * @return the hostname, or null if not found.
     */
    public static String extract(byte[] payload, int length) {
        if (!isTLSClientHello(payload, length)) return null;

        int offset = 5; // skip TLS record header (5 bytes)

        // Skip handshake header: type(1) + length(3) = 4 bytes
        // offset += 4;
        offset += 4;

        // Client Hello body: skip version(2) + random(32)
        offset += 2 + 32;

        // Session ID
        if (offset >= length) return null;
        int sessionIdLength = payload[offset] & 0xFF;
        offset += 1 + sessionIdLength;

        // Cipher suites
        if (offset + 2 > length) return null;
        int cipherSuitesLength = readUint16BE(payload, offset);
        offset += 2 + cipherSuitesLength;

        // Compression methods
        if (offset >= length) return null;
        int compressionMethodsLength = payload[offset] & 0xFF;
        offset += 1 + compressionMethodsLength;

        // Extensions
        if (offset + 2 > length) return null;
        int extensionsLength = readUint16BE(payload, offset);
        offset += 2;

        int extensionsEnd = offset + extensionsLength;
        if (extensionsEnd > length) {
            extensionsEnd = length; // truncated, but try anyway
        }

        while (offset + 4 <= extensionsEnd) {
            int extensionType = readUint16BE(payload, offset);
            int extensionLength = readUint16BE(payload, offset + 2);
            offset += 4;

            if (offset + extensionLength > extensionsEnd) break;

            if (extensionType == EXTENSION_SNI) {
                if (extensionLength < 5) break;

                int sniListLength = readUint16BE(payload, offset);
                if (sniListLength < 3) break;

                int sniType = payload[offset + 2] & 0xFF;
                int sniLength = readUint16BE(payload, offset + 3);

                if (sniType != SNI_TYPE_HOSTNAME) break;
                if (sniLength > extensionLength - 5) break;

                return new String(payload, offset + 5, sniLength);
            }

            offset += extensionLength;
        }

        return null;
    }

    private static int readUint16BE(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }
}
