/*
 * Copyright 2017-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.onosproject.p4dma.pipeconf;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Lists;
import org.onlab.packet.DeserializationException;
import org.onlab.packet.Ethernet;
import org.onlab.util.ImmutableByteSequence;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Port;
import org.onosproject.net.PortNumber;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.driver.AbstractHandlerBehaviour;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.instructions.Instruction;
import org.onosproject.net.flow.instructions.Instructions.OutputInstruction;
import org.onosproject.net.packet.DefaultInboundPacket;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.pi.model.*;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.onosproject.net.pi.runtime.PiPacketMetadata;
import org.onosproject.net.pi.runtime.PiPacketOperation;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.onlab.util.ImmutableByteSequence.copyFrom;
import static org.onosproject.net.PortNumber.CONTROLLER;
import static org.onosproject.net.PortNumber.FLOOD;
import static org.onosproject.net.flow.instructions.Instruction.Type.OUTPUT;
import static org.onosproject.net.pi.model.PiPacketOperationType.PACKET_OUT;

/**
 * Implementation of a pipeline interpreter for the dma.p4 program.
 */
public final class PipelineInterpreterImpl extends AbstractHandlerBehaviour implements PiPipelineInterpreter {

    private static final String DOT                 = ".";
    private static final String HDR                 = "hdr";
    private static final String C_INGRESS           = "c_ingress";
    private static final String T_FWD               = "t_fwd";
    private static final String EGRESS_PORT         = "egress_port";
    private static final String INGRESS_PORT        = "ingress_port";
    private static final String ETHERNET            = "ethernet";
    private static final String IPV4                = "ipv4";
    private static final String STANDARD_METADATA   = "standard_metadata";
    private static final String TIMESTAMP           = "timestamp";
    private static final String IP_SRC              = "ip_src";
    private static final String IP_DST              = "ip_dst";
    private static final String IP_PROTO            = "ip_proto";
    private static final String PORT_SRC            = "port_src";
    private static final String PORT_DST            = "port_dst";
    private static final String TCP_FLAGS           = "tcp_flags";
    private static final String ICMP_TYPE           = "icmp_type";
    private static final String ICMP_CODE           = "icmp_code";
    private static final String CM                  = "cm";
    private static final String BM_IP_SRC           = "bm_ip_src";
    private static final String BM_IP_DST           = "bm_ip_dst";
    private static final String BM_IP_SRC_PORT_SRC  = "bm_ip_src_port_src";
    private static final String BM_IP_SRC_PORT_DST  = "bm_ip_src_port_dst";
    private static final String BM_IP_DST_PORT_SRC  = "bm_ip_dst_port_src";
    private static final String BM_IP_DST_PORT_DST  = "bm_ip_dst_port_dst";
    private static final String AMS                 = "ams";
    private static final String MV                  = "mv";
    private static final int PORT_FIELD_BITWIDTH    = 9;

    private static final String TCP     = "tcp";
    private static final String UDP     = "udp";
    private static final String ICMP    = "icmp";

    private static final PiMatchFieldId INGRESS_PORT_ID = PiMatchFieldId.of(STANDARD_METADATA + DOT + "ingress_port");
    private static final PiMatchFieldId ETH_DST_ID      = PiMatchFieldId.of(HDR + DOT + ETHERNET + DOT + "dst_addr");
    private static final PiMatchFieldId ETH_SRC_ID      = PiMatchFieldId.of(HDR + DOT + ETHERNET + DOT + "src_addr");
    private static final PiMatchFieldId IPV4_SRC_ID     = PiMatchFieldId.of(HDR + DOT + IPV4 + DOT + "src_addr");
    private static final PiMatchFieldId IPV4_DST_ID     = PiMatchFieldId.of(HDR + DOT + IPV4 + DOT + "dst_addr");
    private static final PiMatchFieldId IPV4_PROTO_ID   = PiMatchFieldId.of(HDR + DOT + IPV4 + DOT + "protocol");
    private static final PiMatchFieldId TCP_SRC_ID      = PiMatchFieldId.of(HDR + DOT + TCP + DOT + "src_port");
    private static final PiMatchFieldId TCP_DST_ID      = PiMatchFieldId.of(HDR + DOT + TCP + DOT + "dst_port");
    private static final PiMatchFieldId UDP_SRC_ID      = PiMatchFieldId.of(HDR + DOT + UDP + DOT + "src_port");
    private static final PiMatchFieldId UDP_DST_ID      = PiMatchFieldId.of(HDR + DOT + UDP + DOT + "dst_port");
    private static final PiMatchFieldId TCP_FLAGS_ID    = PiMatchFieldId.of(HDR + DOT + TCP + DOT + "flags");
    private static final PiMatchFieldId ICMP_TYPE_ID    = PiMatchFieldId.of(HDR + DOT + ICMP + DOT + "type");
    private static final PiMatchFieldId ICMP_CODE_ID    = PiMatchFieldId.of(HDR + DOT + ICMP + DOT + "code");
    private static final PiMatchFieldId ETH_TYPE_ID     = PiMatchFieldId.of(HDR + DOT + ETHERNET + DOT + "ether_type");

    private static final PiTableId TABLE_FWD_ID = PiTableId.of(C_INGRESS + DOT + T_FWD);

    private static final PiActionId ACT_ID_NOP              = PiActionId.of("NoAction");
    private static final PiActionId ACT_ID_SEND_TO_CPU      = PiActionId.of(C_INGRESS + DOT + "send_to_cpu");
    private static final PiActionId ACT_ID_SET_EGRESS_PORT  = PiActionId.of(C_INGRESS + DOT + "set_out_port");

    private static final PiActionParamId ACT_PARAM_ID_PORT = PiActionParamId.of("port");

    private static final Map<Integer, PiTableId> TABLE_MAP = new ImmutableMap.Builder<Integer, PiTableId>()
            .put(0, TABLE_FWD_ID)
            .build();

    private static final Map<Criterion.Type, PiMatchFieldId> CRITERION_MAP =
            ImmutableMap.<Criterion.Type, PiMatchFieldId>builder()
                    .put(Criterion.Type.IN_PORT, INGRESS_PORT_ID)
                    .put(Criterion.Type.ETH_DST, ETH_DST_ID)
                    .put(Criterion.Type.ETH_SRC, ETH_SRC_ID)
                    .put(Criterion.Type.ETH_TYPE, ETH_TYPE_ID)
                    .put(Criterion.Type.IPV4_SRC, IPV4_SRC_ID)
                    .put(Criterion.Type.IPV4_DST, IPV4_DST_ID)
                    .put(Criterion.Type.IP_PROTO, IPV4_PROTO_ID)
                    .put(Criterion.Type.TCP_SRC, TCP_SRC_ID)
                    .put(Criterion.Type.TCP_DST, TCP_DST_ID)
                    .put(Criterion.Type.UDP_SRC, UDP_SRC_ID)
                    .put(Criterion.Type.UDP_DST, UDP_DST_ID)
                    .put(Criterion.Type.TCP_FLAGS, TCP_FLAGS_ID)
                    .put(Criterion.Type.ICMPV4_TYPE, ICMP_TYPE_ID)
                    .put(Criterion.Type.ICMPV4_CODE, ICMP_CODE_ID)
                    .build();

    private static final int sizeOfIntInHalfBytes = 8;
    private static final int numberOfBitsInAHalfByte = 4;
    private static final int halfByte = 0x0F;
    private static final char[] hexDigits = { 
    '0', '1', '2', '3', '4', '5', '6', '7', 
    '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
    };

    @Override
    public Optional<PiMatchFieldId> mapCriterionType(Criterion.Type type) {
        return Optional.ofNullable(CRITERION_MAP.get(type));
    }

    @Override
    public Optional<PiTableId> mapFlowRuleTableId(int flowRuleTableId) {
        return Optional.ofNullable(TABLE_MAP.get(flowRuleTableId));
    }

    @Override
    public PiAction mapTreatment(TrafficTreatment treatment, PiTableId piTableId) throws PiInterpreterException {

        if (piTableId != TABLE_FWD_ID) {
            throw new PiInterpreterException(
                    "Can map treatments only for 't_fwd' table");
        }

        if (treatment.allInstructions().size() == 0) {
            // 0 instructions means "NoAction"
            return PiAction.builder().withId(ACT_ID_NOP).build();
        } else if (treatment.allInstructions().size() > 1) {
            // We understand treatments with only 1 instruction.
            throw new PiInterpreterException("Treatment has multiple instructions");
        }

        // Get the first and only instruction.
        Instruction instruction = treatment.allInstructions().get(0);

        if (instruction.type() != OUTPUT) {
            // We can map only instructions of type OUTPUT.
            throw new PiInterpreterException(format(
                    "Instruction of type '%s' not supported", instruction.type()));
        }

        OutputInstruction outInstruction = (OutputInstruction) instruction;
        PortNumber port = outInstruction.port();
        if (!port.isLogical()) {
            return PiAction.builder()
                    .withId(ACT_ID_SET_EGRESS_PORT)
                    .withParameter(new PiActionParam(
                            ACT_PARAM_ID_PORT, copyFrom(port.toLong())))
                    .build();
        } else if (port.equals(CONTROLLER)) {
            return PiAction.builder()
                    .withId(ACT_ID_SEND_TO_CPU)
                    .build();
        } else {
            throw new PiInterpreterException(format(
                    "Output on logical port '%s' not supported", port));
        }
    }

    @Override
    public Collection<PiPacketOperation> mapOutboundPacket(OutboundPacket packet) throws PiInterpreterException {

        TrafficTreatment treatment = packet.treatment();

        // We support only packet-out with OUTPUT instructions.
        if (treatment.allInstructions().size() != 1 &&
                treatment.allInstructions().get(0).type() != OUTPUT) {
            throw new PiInterpreterException(
                    "Treatment not supported: " + treatment.toString());
        }

        Instruction instruction = treatment.allInstructions().get(0);
        PortNumber port = ((OutputInstruction) instruction).port();
        List<PiPacketOperation> piPacketOps = Lists.newArrayList();

        if (!port.isLogical()) {
            piPacketOps.add(createPiPacketOp(packet.data(), port.toLong()));
        } else if (port.equals(FLOOD)) {
            // Since dma.p4 does not support flooding, we create a packet
            // operation for each switch port.
            DeviceService deviceService = handler().get(DeviceService.class);
            DeviceId deviceId = packet.sendThrough();
            for (Port p : deviceService.getPorts(deviceId)) {
                piPacketOps.add(createPiPacketOp(packet.data(), p.number().toLong()));
            }
        } else {
            throw new PiInterpreterException(format(
                    "Output on logical port '%s' not supported", port));
        }

        return piPacketOps;
    }

    @Override
    public InboundPacket mapInboundPacket(PiPacketOperation packetIn, DeviceId deviceId) throws PiInterpreterException {
        
        // We assume that the packet is ethernet, which is fine since mytunnel.p4 can deparse only ethernet packets.
        Ethernet ethPkt;       

        try {
            ethPkt = Ethernet.deserializer().deserialize(packetIn.data().asArray(), 0, packetIn.data().size());
        } catch (DeserializationException dex) {
            throw new PiInterpreterException(dex.getMessage());
        }

        // Returns the ingress port packet metadata.
        Optional<PiPacketMetadata> packetMetadataIngress = packetIn.metadatas().stream()
                .filter(metadata -> metadata.id().toString().equals(INGRESS_PORT))
                .findFirst();

        Optional<PiPacketMetadata> packetMetadataIpSrc = packetIn.metadatas().stream()
                .filter(metadata -> metadata.id().toString().equals(IP_SRC))
                .findFirst();

        Optional<PiPacketMetadata> packetMetadataIpDst = packetIn.metadatas().stream()
                .filter(metadata -> metadata.id().toString().equals(IP_DST))
                .findFirst();

        if (packetMetadataIpDst.isPresent() && packetMetadataIpSrc.isPresent()) {

            ByteBuffer[] packetMetadataArray = new ByteBuffer[18];

            ByteBuffer ipSrcBB = packetMetadataIpSrc.get().value().asReadOnlyBuffer();
            ByteBuffer ipDstBB = packetMetadataIpDst.get().value().asReadOnlyBuffer();

            packetMetadataArray[1] = ipSrcBB;
            packetMetadataArray[2] = ipDstBB;

            Optional<PiPacketMetadata> packetMetadataTs = packetIn.metadatas().stream()
                    .filter(metadata -> metadata.id().toString().equals(TIMESTAMP))
                    .findFirst();

            packetMetadataTs.ifPresent(
                    piPacketMetadata -> packetMetadataArray[0] = piPacketMetadata.value().asReadOnlyBuffer());

            Optional<PiPacketMetadata> packetMetadataIpProto = packetIn.metadatas().stream()
                    .filter(metadata -> metadata.id().toString().equals(IP_PROTO))
                    .findFirst();

            packetMetadataIpProto.ifPresent(
                    piPacketMetadata -> packetMetadataArray[3] = piPacketMetadata.value().asReadOnlyBuffer());

            Optional<PiPacketMetadata> packetMetadataPortSrc = packetIn.metadatas().stream()
                    .filter(metadata -> metadata.id().toString().equals(PORT_SRC))
                    .findFirst();

            packetMetadataPortSrc.ifPresent(
                    piPacketMetadata -> packetMetadataArray[4] = piPacketMetadata.value().asReadOnlyBuffer());

            Optional<PiPacketMetadata> packetMetadataPortDst = packetIn.metadatas().stream()
                    .filter(metadata -> metadata.id().toString().equals(PORT_DST))
                    .findFirst();

            packetMetadataPortDst.ifPresent(
                    piPacketMetadata -> packetMetadataArray[5] = piPacketMetadata.value().asReadOnlyBuffer());

            Optional<PiPacketMetadata> packetMetadataTcpFlags = packetIn.metadatas().stream()
                    .filter(metadata -> metadata.id().toString().equals(TCP_FLAGS))
                    .findFirst();

            packetMetadataTcpFlags.ifPresent(
                    piPacketMetadata -> packetMetadataArray[6] = piPacketMetadata.value().asReadOnlyBuffer());

            Optional<PiPacketMetadata> packetMetadataIcmpType = packetIn.metadatas().stream()
                    .filter(metadata -> metadata.id().toString().equals(ICMP_TYPE))
                    .findFirst();

            packetMetadataIcmpType.ifPresent(
                    piPacketMetadata -> packetMetadataArray[7] = piPacketMetadata.value().asReadOnlyBuffer());

            Optional<PiPacketMetadata> packetMetadataIcmpCode = packetIn.metadatas().stream()
                    .filter(metadata -> metadata.id().toString().equals(ICMP_CODE))
                    .findFirst();

            packetMetadataIcmpCode.ifPresent(
                    piPacketMetadata -> packetMetadataArray[8] = piPacketMetadata.value().asReadOnlyBuffer());

            Optional<PiPacketMetadata> packetMetadataCm = packetIn.metadatas().stream()
                    .filter(metadata -> metadata.id().toString().equals(CM))
                    .findFirst();

            packetMetadataCm.ifPresent(
                    piPacketMetadata -> packetMetadataArray[9] = piPacketMetadata.value().asReadOnlyBuffer());

            Optional<PiPacketMetadata> packetMetadataBmIpSrc = packetIn.metadatas().stream()
                    .filter(metadata -> metadata.id().toString().equals(BM_IP_SRC))
                    .findFirst();

            packetMetadataBmIpSrc.ifPresent(
                    piPacketMetadata -> packetMetadataArray[10] = piPacketMetadata.value().asReadOnlyBuffer());

            Optional<PiPacketMetadata> packetMetadataBmIpDst = packetIn.metadatas().stream()
                    .filter(metadata -> metadata.id().toString().equals(BM_IP_DST))
                    .findFirst();

            packetMetadataBmIpDst.ifPresent(
                    piPacketMetadata -> packetMetadataArray[11] = piPacketMetadata.value().asReadOnlyBuffer());

            Optional<PiPacketMetadata> packetMetadataBmIpSrcPortSrc = packetIn.metadatas().stream()
                    .filter(metadata -> metadata.id().toString().equals(BM_IP_SRC_PORT_SRC))
                    .findFirst();

            packetMetadataBmIpSrcPortSrc.ifPresent(
                    piPacketMetadata -> packetMetadataArray[12] = piPacketMetadata.value().asReadOnlyBuffer());

            Optional<PiPacketMetadata> packetMetadataBmIpSrcPortDst = packetIn.metadatas().stream()
                    .filter(metadata -> metadata.id().toString().equals(BM_IP_SRC_PORT_DST))
                    .findFirst();

            packetMetadataBmIpSrcPortDst.ifPresent(
                    piPacketMetadata -> packetMetadataArray[13] = piPacketMetadata.value().asReadOnlyBuffer());

            Optional<PiPacketMetadata> packetMetadataBmIpDstPortSrc = packetIn.metadatas().stream()
                    .filter(metadata -> metadata.id().toString().equals(BM_IP_DST_PORT_SRC))
                    .findFirst();

            packetMetadataBmIpDstPortSrc.ifPresent(
                    piPacketMetadata -> packetMetadataArray[14] = piPacketMetadata.value().asReadOnlyBuffer());

            Optional<PiPacketMetadata> packetMetadataBmIpDstPortDst = packetIn.metadatas().stream()
                    .filter(metadata -> metadata.id().toString().equals(BM_IP_DST_PORT_DST))
                    .findFirst();

            packetMetadataBmIpDstPortDst.ifPresent(
                    piPacketMetadata -> packetMetadataArray[15] = piPacketMetadata.value().asReadOnlyBuffer());

            Optional<PiPacketMetadata> packetMetadataAms = packetIn.metadatas().stream()
                    .filter(metadata -> metadata.id().toString().equals(AMS))
                    .findFirst();

            packetMetadataAms.ifPresent(
                    piPacketMetadata -> packetMetadataArray[16] = piPacketMetadata.value().asReadOnlyBuffer());

            Optional<PiPacketMetadata> packetMetadataMv = packetIn.metadatas().stream()
                    .filter(metadata -> metadata.id().toString().equals(MV))
                    .findFirst();

            packetMetadataMv.ifPresent(
                    piPacketMetadata -> packetMetadataArray[17] = piPacketMetadata.value().asReadOnlyBuffer());

            retrievePacketMetadata(packetMetadataArray);
        }

        if (packetMetadataIngress.isPresent()) {
            short s = packetMetadataIngress.get().value().asReadOnlyBuffer().getShort();
            ConnectPoint receivedFrom = new ConnectPoint(deviceId, PortNumber.portNumber(s));
            return new DefaultInboundPacket(receivedFrom, ethPkt, packetIn.data().asReadOnlyBuffer());
        } else {
            throw new PiInterpreterException(format(
                    "Missing metadata '%s' in packet-in received from '%s': %s",
                    INGRESS_PORT, deviceId, packetIn));
        }                 
    }

    private PiPacketOperation createPiPacketOp(ByteBuffer data, long portNumber)
            throws PiInterpreterException {
        PiPacketMetadata metadata = createPacketMetadata(portNumber);
        return PiPacketOperation.builder()
                .withType(PACKET_OUT)
                .withData(copyFrom(data))
                .withMetadatas(ImmutableList.of(metadata))
                .build();
    }

    private PiPacketMetadata createPacketMetadata(long portNumber)
            throws PiInterpreterException {
        try {
            return PiPacketMetadata.builder()
                    .withId(PiPacketMetadataId.of(EGRESS_PORT))
                    .withValue(copyFrom(portNumber).fit(PORT_FIELD_BITWIDTH))
                    .build();
        } catch (ImmutableByteSequence.ByteSequenceTrimException e) {
            throw new PiInterpreterException(format(
                    "Port number %d too big, %s", portNumber, e.getMessage()));
        }
    }

    public static String decToHex(int dec) {
        StringBuilder hexBuilder = new StringBuilder(sizeOfIntInHalfBytes);
        hexBuilder.setLength(sizeOfIntInHalfBytes);
        for (int i = sizeOfIntInHalfBytes - 1; i >= 0; --i)
        {
          int j = dec & halfByte;
          hexBuilder.setCharAt(i, hexDigits[j]);
          dec >>= numberOfBitsInAHalfByte;
        }
        return hexBuilder.toString(); 
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    public void retrievePacketMetadata(ByteBuffer[] packetMetadataArray) {

        try {

            String tsString = Long.toString(packetMetadataArray[0].getLong());

            String ipSrcHex = decToHex(packetMetadataArray[1].getInt());
            String ipSrcString = InetAddress.getByAddress(hexStringToByteArray(ipSrcHex)).toString().split("/")[1];

            String ipDstHex = decToHex(packetMetadataArray[2].getInt());
            String ipDstString = InetAddress.getByAddress(hexStringToByteArray(ipDstHex)).toString().split("/")[1];

            short ipProto = packetMetadataArray[3].getShort();
            String ipProtoString;
            if (ipProto > 0) {
                ipProtoString = Short.toString(ipProto);
            } else {
                String ipProtoHex = decToHex(ipProto & 0xffff);
                int ipProtoParsed = (int) Long.parseLong(ipProtoHex, 16);
                ipProtoString = Integer.toString(ipProtoParsed);
            }

            short portSrc = packetMetadataArray[4].getShort();
            String portSrcString;
            if (portSrc > 0) {
                portSrcString = Short.toString(portSrc);
            } else {
                String portSrcHex = decToHex(portSrc & 0xffff);
                int portSrcParsed = (int) Long.parseLong(portSrcHex, 16);
                portSrcString = Integer.toString(portSrcParsed);
            }

            short portDst = packetMetadataArray[5].getShort();
            String portDstString;
            if (portDst > 0) {
                portDstString = Short.toString(portDst);
            } else {
                String portDstHex = decToHex(portDst & 0xffff);
                int portDstParsed = (int) Long.parseLong(portDstHex, 16);
                portDstString = Integer.toString(portDstParsed);
            }

            short tcpFlags = packetMetadataArray[6].getShort();
            String tcpFlagsString;
            if (tcpFlags > 0) {
                tcpFlagsString = Short.toString(tcpFlags);
            } else {
                String tcpFlagsHex = decToHex(tcpFlags & 0xffff);
                int tcpFlagsParsed = (int) Long.parseLong(tcpFlagsHex, 16);
                tcpFlagsString = Integer.toString(tcpFlagsParsed);
            }

            short icmpType = packetMetadataArray[7].getShort();
            String icmpTypeString;
            if (icmpType > 0) {
                icmpTypeString = Short.toString(icmpType);
            } else {
                String icmpTypeHex = decToHex(icmpType & 0xffff);
                int icmpTypeParsed = (int) Long.parseLong(icmpTypeHex, 16);
                icmpTypeString = Integer.toString(icmpTypeParsed);
            }

            short icmpCode = packetMetadataArray[8].getShort();
            String icmpCodeString;
            if (icmpCode > 0) {
                icmpCodeString = Short.toString(icmpCode);
            } else {
                String icmpCodeHex = decToHex(icmpCode & 0xffff);
                int icmpCodeParsed = (int) Long.parseLong(icmpCodeHex, 16);
                icmpCodeString = Integer.toString(icmpCodeParsed);
            }

            String cmString = Integer.toString(packetMetadataArray[9].getInt());
            String bmIpSrcString = Integer.toString(packetMetadataArray[10].getInt());
            String bmIpDstString = Integer.toString(packetMetadataArray[11].getInt());
            String bmIpSrcPortSrcString = Integer.toString(packetMetadataArray[12].getInt());
            String bmIpSrcPortDstString = Integer.toString(packetMetadataArray[13].getInt());
            String bmIpDstPortSrcString = Integer.toString(packetMetadataArray[14].getInt());
            String bmIpDstPortDstString = Integer.toString(packetMetadataArray[15].getInt());
            String amsString = Integer.toString(packetMetadataArray[16].getInt());

            short mv = packetMetadataArray[17].getShort();
            String mvString;
            if (mv > 0) {
                mvString = Short.toString(mv);
            } else {
                String mvHex = decToHex(mv & 0xffff);
                int mvParsed = (int) Long.parseLong(mvHex, 16);
                mvString = Integer.toString(mvParsed);
            }

            if ((!ipSrcString.equals("0")) &&
                (!ipDstString.equals("0")) &&
                (!ipSrcString.equals("10.0.0.1")) &&
                (!ipSrcString.equals("10.0.0.2"))) {

                String dma =
                        "{\"initial_ts\": \"" + tsString + "\" , " +
                        "\"current_ts\": \"" + tsString + "\" , " +
                        "\"ip_src\": \"" + ipSrcString + "\" , " +
                        "\"ip_dst\": \"" + ipDstString + "\" , " +
                        "\"ip_proto\": \"" + ipProtoString + "\" , " +
                        "\"port_src\": \"" + portSrcString + "\" , " +
                        "\"port_dst\": \"" + portDstString + "\" , " +
                        "\"tcp_flags\": \"" + tcpFlagsString + "\" , " +
                        "\"icmp_type\": \"" + icmpTypeString + "\" , " +
                        "\"icmp_code\": \"" + icmpCodeString + "\" , " +
                        "\"cm\": \"" + cmString + "\" , " +
                        "\"bm_ip_src\": \"" + bmIpSrcString + "\" , " +
                        "\"bm_ip_dst\": \"" + bmIpDstString + "\" , " +
                        "\"bm_ip_src_port_src\": \"" + bmIpSrcPortSrcString + "\" , " +
                        "\"bm_ip_src_port_dst\": \"" + bmIpSrcPortDstString + "\" , " +
                        "\"bm_ip_dst_port_src\": \"" + bmIpDstPortSrcString + "\" , " +
                        "\"bm_ip_dst_port_dst\": \"" + bmIpDstPortDstString + "\" , " +
                        "\"ams\": \"" + amsString + "\" , " +
                        "\"mv\": \"" + mvString + "\"}";

                dmaPost(dma);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void dmaPost(String dma) {

        HttpURLConnection conn;
        DataOutputStream os;

        try {

            URL url = new URL("http://127.0.0.1:5000/add/"); //important to add the trailing slash after add

            byte[] postData = dma.getBytes(StandardCharsets.UTF_8);
            
            conn = (HttpURLConnection) url.openConnection();
            conn.setDoOutput(true);
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty( "charset", "utf-8");
            conn.setRequestProperty("Content-Length", Integer.toString(dma.length()));
            
            os = new DataOutputStream(conn.getOutputStream());
            os.write(postData);
            os.flush();

            if (conn.getResponseCode() != 200) {
                throw new RuntimeException("Failed : HTTP error code : " + conn.getResponseCode());
            }

            conn.disconnect();

        } catch (IOException e) {
            e.printStackTrace();
        }        
    }
}