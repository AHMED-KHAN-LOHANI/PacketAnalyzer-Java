package com.dpi.engine.parser;

import com.dpi.engine.model.ParsedPacket;
import com.dpi.engine.model.RawPacket;

/**
 * Parses raw packet bytes into structured protocol fields.
 * Supports Ethernet II / IPv4 / TCP / UDP.
 */
public class PacketParser {

    private static final int ETHERNET_HEADER_SIZE = 14;
    private static final int ETHERTYPE_IPV4 = 0x0800;
    private static final int IP_PROTOCOL_TCP = 6;
    private static final int IP_PROTOCOL_UDP = 17;

    /** Parse a raw packet into a structured parsed packet. */
    public static boolean parse(RawPacket raw, ParsedPacket parsed) {
        byte[] data = raw.getData();
        int len = data.length;

        // Need at least Ethernet header
        if (len < ETHERNET_HEADER_SIZE) return false;

        int offset = 0;

        // --- Ethernet Header (14 bytes) ---
        parsed.setDestMac(formatMac(data, offset)); offset += 6;
        parsed.setSrcMac(formatMac(data, offset));  offset += 6;
        int etherType = ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
        parsed.setEtherType(etherType);
        parsed.setHasEthernet(true);
        offset += 2;

        if (etherType != ETHERTYPE_IPV4) return true; // non-IPv4, stop here

        // --- IPv4 Header ---
        if (offset + 20 > len) return true;
        int ipVersion = (data[offset] >> 4) & 0x0F;
        int ipHeaderLen = (data[offset] & 0x0F) * 4;
        if (ipVersion != 4 || ipHeaderLen < 20) return true;

        parsed.setTtl(data[offset + 8] & 0xFF);
        parsed.setProtocol(data[offset + 9] & 0xFF);
        parsed.setSrcIp(formatIp(data, offset + 12));
        parsed.setDestIp(formatIp(data, offset + 16));
        parsed.setIpHeaderLength(ipHeaderLen);
        parsed.setHasIpv4(true);
        offset += ipHeaderLen;

        int protocol = parsed.getProtocol();

        if (protocol == IP_PROTOCOL_TCP) {
            // --- TCP Header ---
            if (offset + 20 > len) return true;
            parsed.setSrcPort(((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF));
            parsed.setDestPort(((data[offset + 2] & 0xFF) << 8) | (data[offset + 3] & 0xFF));
            parsed.setSeqNumber(readUint32BE(data, offset + 4));
            parsed.setAckNumber(readUint32BE(data, offset + 8));
            int dataOff = (data[offset + 12] >> 4) * 4;
            parsed.setDataOffset(dataOff);
            byte flags = data[offset + 13];
            parsed.setFin((flags & 0x01) != 0);
            parsed.setSyn((flags & 0x02) != 0);
            parsed.setRst((flags & 0x04) != 0);
            parsed.setPsh((flags & 0x08) != 0);
            parsed.setAck((flags & 0x10) != 0);
            parsed.setHasTcp(true);
            offset += dataOff;
        } else if (protocol == IP_PROTOCOL_UDP) {
            // --- UDP Header (8 bytes) ---
            if (offset + 8 > len) return true;
            parsed.setSrcPort(((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF));
            parsed.setDestPort(((data[offset + 2] & 0xFF) << 8) | (data[offset + 3] & 0xFF));
            parsed.setUdpLength(((data[offset + 4] & 0xFF) << 8) | (data[offset + 5] & 0xFF));
            parsed.setHasUdp(true);
            offset += 8;
        }

        // --- Payload ---
        if (offset < len) {
            int payloadLen = len - offset;
            byte[] payload = new byte[payloadLen];
            System.arraycopy(data, offset, payload, 0, payloadLen);
            parsed.setPayload(payload);
            parsed.setPayloadOffset(offset);
            parsed.setPayloadLength(payloadLen);
        } else {
            parsed.setPayload(new byte[0]);
            parsed.setPayloadLength(0);
        }

        parsed.buildFiveTuple();
        return true;
    }

    private static String formatMac(byte[] data, int offset) {
        return String.format("%02X:%02X:%02X:%02X:%02X:%02X",
                data[offset] & 0xFF, data[offset + 1] & 0xFF,
                data[offset + 2] & 0xFF, data[offset + 3] & 0xFF,
                data[offset + 4] & 0xFF, data[offset + 5] & 0xFF);
    }

    private static String formatIp(byte[] data, int offset) {
        return String.format("%d.%d.%d.%d",
                data[offset] & 0xFF, data[offset + 1] & 0xFF,
                data[offset + 2] & 0xFF, data[offset + 3] & 0xFF);
    }

    private static long readUint32BE(byte[] data, int offset) {
        return ((long) (data[offset] & 0xFF) << 24)
             | ((long) (data[offset + 1] & 0xFF) << 16)
             | ((long) (data[offset + 2] & 0xFF) << 8)
             | ((long) (data[offset + 3] & 0xFF));
    }
}
