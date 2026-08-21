/*
 * Decompiled with CFR 0.152.
 */
package com.dpi.engine.parser;

import com.dpi.engine.model.ParsedPacket;
import com.dpi.engine.model.RawPacket;

public class PacketParser {
    private static final int ETHERNET_HEADER_SIZE = 14;
    private static final int ETHERTYPE_IPV4 = 2048;
    private static final int IP_PROTOCOL_TCP = 6;
    private static final int IP_PROTOCOL_UDP = 17;

    public static boolean parse(RawPacket raw, ParsedPacket parsed) {
        byte[] data = raw.getData();
        int len = data.length;
        if (len < 14) {
            return false;
        }
        int offset = 0;
        parsed.setDestMac(PacketParser.formatMac(data, offset));
        parsed.setSrcMac(PacketParser.formatMac(data, offset += 6));
        int etherType = (data[offset += 6] & 0xFF) << 8 | data[offset + 1] & 0xFF;
        parsed.setEtherType(etherType);
        parsed.setHasEthernet(true);
        offset += 2;
        if (etherType != 2048) {
            return true;
        }
        if (offset + 20 > len) {
            return true;
        }
        int ipVersion = data[offset] >> 4 & 0xF;
        int ipHeaderLen = (data[offset] & 0xF) * 4;
        if (ipVersion != 4 || ipHeaderLen < 20) {
            return true;
        }
        parsed.setTtl(data[offset + 8] & 0xFF);
        parsed.setProtocol(data[offset + 9] & 0xFF);
        parsed.setSrcIp(PacketParser.formatIp(data, offset + 12));
        parsed.setDestIp(PacketParser.formatIp(data, offset + 16));
        parsed.setIpHeaderLength(ipHeaderLen);
        parsed.setHasIpv4(true);
        offset += ipHeaderLen;
        int protocol = parsed.getProtocol();
        if (protocol == 6) {
            if (offset + 20 > len) {
                return true;
            }
            parsed.setSrcPort((data[offset] & 0xFF) << 8 | data[offset + 1] & 0xFF);
            parsed.setDestPort((data[offset + 2] & 0xFF) << 8 | data[offset + 3] & 0xFF);
            parsed.setSeqNumber(PacketParser.readUint32BE(data, offset + 4));
            parsed.setAckNumber(PacketParser.readUint32BE(data, offset + 8));
            int dataOff = (data[offset + 12] >> 4) * 4;
            parsed.setDataOffset(dataOff);
            byte flags = data[offset + 13];
            parsed.setFin((flags & 1) != 0);
            parsed.setSyn((flags & 2) != 0);
            parsed.setRst((flags & 4) != 0);
            parsed.setPsh((flags & 8) != 0);
            parsed.setAck((flags & 0x10) != 0);
            parsed.setHasTcp(true);
            offset += dataOff;
        } else if (protocol == 17) {
            if (offset + 8 > len) {
                return true;
            }
            parsed.setSrcPort((data[offset] & 0xFF) << 8 | data[offset + 1] & 0xFF);
            parsed.setDestPort((data[offset + 2] & 0xFF) << 8 | data[offset + 3] & 0xFF);
            parsed.setUdpLength((data[offset + 4] & 0xFF) << 8 | data[offset + 5] & 0xFF);
            parsed.setHasUdp(true);
            offset += 8;
        }
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
        return String.format("%02X:%02X:%02X:%02X:%02X:%02X", data[offset] & 0xFF, data[offset + 1] & 0xFF, data[offset + 2] & 0xFF, data[offset + 3] & 0xFF, data[offset + 4] & 0xFF, data[offset + 5] & 0xFF);
    }

    private static String formatIp(byte[] data, int offset) {
        return String.format("%d.%d.%d.%d", data[offset] & 0xFF, data[offset + 1] & 0xFF, data[offset + 2] & 0xFF, data[offset + 3] & 0xFF);
    }

    private static long readUint32BE(byte[] data, int offset) {
        return (long)(data[offset] & 0xFF) << 24 | (long)(data[offset + 1] & 0xFF) << 16 | (long)(data[offset + 2] & 0xFF) << 8 | (long)(data[offset + 3] & 0xFF);
    }
}

