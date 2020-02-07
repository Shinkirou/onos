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

package org.onosproject.p4flowstats.pipeconf;

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
import org.onosproject.net.pi.model.PiActionId;
import org.onosproject.net.pi.model.PiActionParamId;
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.model.PiPacketMetadataId;
import org.onosproject.net.pi.model.PiPipelineInterpreter;
import org.onosproject.net.pi.model.PiTableId;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.onosproject.net.pi.runtime.PiPacketMetadata;
import org.onosproject.net.pi.runtime.PiPacketOperation;

import java.nio.ByteBuffer;
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

import java.util.Date;
import java.text.SimpleDateFormat;
import java.io.File;
import java.nio.file.Paths;
import java.util.Arrays;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.io.IOException;
import java.nio.LongBuffer;

import java.net.InetAddress;

/**
 * Implementation of a pipeline interpreter for the flowstats.p4 program.
 */
public final class PipelineInterpreterImpl extends AbstractHandlerBehaviour implements PiPipelineInterpreter {

    private static final String DOT                 = ".";
    private static final String HDR                 = "hdr";
    private static final String C_INGRESS           = "c_ingress";
    private static final String T_L2_FWD            = "t_l2_fwd";
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
    private static final String CM_IP               = "cm_ip";
    private static final String CM_5T               = "cm_5t";
    private static final String BM_SRC              = "bm_src";
    private static final String BM_DST              = "bm_dst";
    private static final String AMS                 = "ams";
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

    private static final PiTableId TABLE_L2_FWD_ID = PiTableId.of(C_INGRESS + DOT + T_L2_FWD);

    private static final PiActionId ACT_ID_NOP              = PiActionId.of("NoAction");
    private static final PiActionId ACT_ID_SEND_TO_CPU      = PiActionId.of(C_INGRESS + DOT + "send_to_cpu");
    private static final PiActionId ACT_ID_SET_EGRESS_PORT  = PiActionId.of(C_INGRESS + DOT + "set_out_port");

    private static final PiActionParamId ACT_PARAM_ID_PORT = PiActionParamId.of("port");

    private static final Map<Integer, PiTableId> TABLE_MAP = new ImmutableMap.Builder<Integer, PiTableId>()
                                                                    .put(0, TABLE_L2_FWD_ID)
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

        if (piTableId != TABLE_L2_FWD_ID) {
            throw new PiInterpreterException(
                    "Can map treatments only for 't_l2_fwd' table");
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
            // Since flowstats.p4 does not support flooding, we create a packet
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
    public InboundPacket mapInboundPacket(PiPacketOperation packetIn, DeviceId deviceId)
            throws PiInterpreterException {
        // We assume that the packet is ethernet, which is fine since mytunnel.p4
        // can deparse only ethernet packets.
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

        // Returns the ingress port packet metadata.
        Optional<PiPacketMetadata> packetMetadataTs = packetIn.metadatas().stream()
                .filter(metadata -> metadata.id().toString().equals(TIMESTAMP))
                .findFirst();

        // Returns the ingress port packet metadata.
        Optional<PiPacketMetadata> packetMetadataIpSrc = packetIn.metadatas().stream()
                .filter(metadata -> metadata.id().toString().equals(IP_SRC))
                .findFirst();  
                
        // Returns the ingress port packet metadata.
        Optional<PiPacketMetadata> packetMetadataIpDst = packetIn.metadatas().stream()
                .filter(metadata -> metadata.id().toString().equals(IP_DST))
                .findFirst();

        // Returns the ingress port packet metadata.
        Optional<PiPacketMetadata> packetMetadataIpProto = packetIn.metadatas().stream()
                .filter(metadata -> metadata.id().toString().equals(IP_PROTO))
                .findFirst();                

        // Returns the ingress port packet metadata.
        Optional<PiPacketMetadata> packetMetadataPortSrc = packetIn.metadatas().stream()
                .filter(metadata -> metadata.id().toString().equals(PORT_SRC))
                .findFirst();

        // Returns the ingress port packet metadata.
        Optional<PiPacketMetadata> packetMetadataPortDst = packetIn.metadatas().stream()
                .filter(metadata -> metadata.id().toString().equals(PORT_DST))
                .findFirst(); 

        // Returns the ingress port packet metadata.
        Optional<PiPacketMetadata> packetMetadataTcpFlags = packetIn.metadatas().stream()
                .filter(metadata -> metadata.id().toString().equals(TCP_FLAGS))
                .findFirst();                

        // Returns the ingress port packet metadata.
        Optional<PiPacketMetadata> packetMetadataIcmpType = packetIn.metadatas().stream()
                .filter(metadata -> metadata.id().toString().equals(ICMP_TYPE))
                .findFirst(); 

        // Returns the ingress port packet metadata.
        Optional<PiPacketMetadata> packetMetadataIcmpCode = packetIn.metadatas().stream()
                .filter(metadata -> metadata.id().toString().equals(ICMP_CODE))
                .findFirst();                 

        // Returns the ingress port packet metadata.
        Optional<PiPacketMetadata> packetMetadataCmIp = packetIn.metadatas().stream()
                .filter(metadata -> metadata.id().toString().equals(CM_IP))
                .findFirst(); 

        // Returns the ingress port packet metadata.
        Optional<PiPacketMetadata> packetMetadataCm5t = packetIn.metadatas().stream()
                .filter(metadata -> metadata.id().toString().equals(CM_5T))
                .findFirst(); 

        // Returns the ingress port packet metadata.
        Optional<PiPacketMetadata> packetMetadataBmSrc = packetIn.metadatas().stream()
                .filter(metadata -> metadata.id().toString().equals(BM_SRC))
                .findFirst(); 

        // Returns the ingress port packet metadata.
        Optional<PiPacketMetadata> packetMetadataBmDst = packetIn.metadatas().stream()
                .filter(metadata -> metadata.id().toString().equals(BM_DST))
                .findFirst();   

        // Returns the ingress port packet metadata.
        Optional<PiPacketMetadata> packetMetadataAms = packetIn.metadatas().stream()
                .filter(metadata -> metadata.id().toString().equals(AMS))
                .findFirst();                                                                                                                               

        try {

            String timeStamp = new SimpleDateFormat("yyyy-MM-dd-HH-mm-ss-SSS").format(new Date());
            String currentUsersHomeDir = System.getProperty("user.home");
            String otherFolder = currentUsersHomeDir + File.separator + "Documents" + File.separator + "flow-stats" + File.separator;
            java.nio.file.Path txtPath = Paths.get(otherFolder + "threshold" + ".csv");             

            if (packetMetadataIpDst.isPresent() && packetMetadataIpSrc.isPresent()) {

                ByteBuffer tsBB = packetMetadataTs.get().value().asReadOnlyBuffer();
                long ts = tsBB.getLong();
                String tsString = Long.toString(ts);
                
                ByteBuffer ipSrcBB = packetMetadataIpSrc.get().value().asReadOnlyBuffer();
                int ipSrc = ipSrcBB.getInt();
                String ipSrcHex = decToHex(ipSrc);
                String ipSrcString = InetAddress.getByAddress(hexStringToByteArray(ipSrcHex)).toString().split("/")[1];

                ByteBuffer ipDstBB = packetMetadataIpDst.get().value().asReadOnlyBuffer();
                int ipDst = ipDstBB.getInt();
                String ipDstHex = decToHex(ipDst);
                String ipDstString = InetAddress.getByAddress(hexStringToByteArray(ipDstHex)).toString().split("/")[1];

                ByteBuffer ipProtoBB = packetMetadataIpProto.get().value().asReadOnlyBuffer();
                short ipProto = ipProtoBB.getShort();
                String ipProtoString = "";
                if (ipProto > 0) {
                    ipProtoString = Short.toString(ipProto);
                } else {
                    String ipProtoHex = decToHex(ipProto & 0xffff);
                    int ipProtoParsed = (int) Long.parseLong(ipProtoHex, 16);
                    ipProtoString = Integer.toString(ipProtoParsed);
                }

                ByteBuffer portSrcBB = packetMetadataPortSrc.get().value().asReadOnlyBuffer();
                short portSrc = portSrcBB.getShort();
                String portSrcString = "";
                if (portSrc > 0) {
                    portSrcString = Short.toString(portSrc);
                } else {
                    String portSrcHex = decToHex(portSrc & 0xffff);
                    int portSrcParsed = (int) Long.parseLong(portSrcHex, 16);
                    portSrcString = Integer.toString(portSrcParsed);
                }

                ByteBuffer portDstBB = packetMetadataPortDst.get().value().asReadOnlyBuffer();
                short portDst = portDstBB.getShort();
                String portDstString = "";
                if (portDst > 0) {
                    portDstString = Short.toString(portDst);
                } else {
                    String portDstHex = decToHex(portDst & 0xffff);
                    int portDstParsed = (int) Long.parseLong(portDstHex, 16);
                    portDstString = Integer.toString(portDstParsed);
                }

                ByteBuffer tcpFlagsBB = packetMetadataTcpFlags.get().value().asReadOnlyBuffer();
                short tcpFlags = tcpFlagsBB.getShort();
                String tcpFlagsString = "";
                if (tcpFlags > 0) {
                    tcpFlagsString = Short.toString(tcpFlags);
                } else {
                    String tcpFlagsHex = decToHex(tcpFlags & 0xffff);
                    int tcpFlagsParsed = (int) Long.parseLong(tcpFlagsHex, 16);
                    tcpFlagsString = Integer.toString(tcpFlagsParsed);
                }                                                

                ByteBuffer icmpTypeBB = packetMetadataIcmpType.get().value().asReadOnlyBuffer();
                short icmpType = icmpTypeBB.getShort();
                String icmpTypeString = "";
                if (icmpType > 0) {
                    icmpTypeString = Short.toString(icmpType);
                } else {
                    String icmpTypeHex = decToHex(icmpType & 0xffff);
                    int icmpTypeParsed = (int) Long.parseLong(icmpTypeHex, 16);
                    icmpTypeString = Integer.toString(icmpTypeParsed);
                }

                ByteBuffer icmpCodeBB = packetMetadataIcmpCode.get().value().asReadOnlyBuffer();
                short icmpCode = icmpCodeBB.getShort();
                String icmpCodeString = ""; 
                if (icmpCode > 0) {
                    icmpCodeString = Short.toString(icmpCode);
                } else {
                    String icmpCodeHex = decToHex(icmpCode & 0xffff);
                    int icmpCodeParsed = (int) Long.parseLong(icmpCodeHex, 16);
                    icmpCodeString = Integer.toString(icmpCodeParsed);
                }                               

                ByteBuffer cmIpBB = packetMetadataCmIp.get().value().asReadOnlyBuffer();
                int cmIp = cmIpBB.getInt();
                String cmIpString = Integer.toString(cmIp);

                ByteBuffer cm5tBB = packetMetadataCm5t.get().value().asReadOnlyBuffer();
                int cm5t = cm5tBB.getInt();
                String cm5tString = Integer.toString(cm5t);

                ByteBuffer bmSrcBB = packetMetadataBmSrc.get().value().asReadOnlyBuffer();
                int bmSrc = bmSrcBB.getInt();
                String bmSrcString = Integer.toString(bmSrc);

                ByteBuffer bmDstBB = packetMetadataBmDst.get().value().asReadOnlyBuffer();
                int bmDst = bmDstBB.getInt();
                String bmDstString = Integer.toString(bmDst);

                ByteBuffer amsBB = packetMetadataAms.get().value().asReadOnlyBuffer();
                int ams = amsBB.getInt();
                String amsString = Integer.toString(ams);                                                                                                

                if ((ipSrc != 0) && (ipDst != 0)) {

                    String flowStats =  tsString + "," + 
                                        ipSrcString + "," +
                                        ipDstString + "," + 
                                        ipProtoString + "," +
                                        portSrcString + "," + 
                                        portDstString + "," +
                                        tcpFlagsString + "," + 
                                        icmpTypeString + "," +
                                        icmpCodeString + "," +
                                        cmIpString + "," +
                                        cm5tString + "," +
                                        bmSrcString + "," +
                                        bmDstString + "," + 
                                        amsString;
                    
                    Files.write(txtPath, Arrays.asList(flowStats), StandardCharsets.UTF_8,
                    Files.exists(txtPath) ? StandardOpenOption.APPEND : StandardOpenOption.CREATE);                    
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
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
}