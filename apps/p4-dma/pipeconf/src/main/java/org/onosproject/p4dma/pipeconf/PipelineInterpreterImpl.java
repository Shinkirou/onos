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
import java.net.UnknownHostException;
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
    private static final String IP_SRC              = "ip_src";
    private static final String IP_DST              = "ip_dst";
    private static final String cm_ip_cnt           = "cm_ip_cnt";
    private static final String cm_ip_len           = "cm_ip_len";
    private static final String cm_ip_len_ss        = "cm_ip_len_ss";
    private static final String cm_ip_port_21_cnt   = "cm_ip_port_21_cnt";
    private static final String cm_ip_port_21_len   = "cm_ip_port_21_len";
    private static final String cm_ip_port_22_cnt   = "cm_ip_port_22_cnt";
    private static final String cm_ip_port_22_len   = "cm_ip_port_22_len";
    private static final String cm_ip_port_80_cnt   = "cm_ip_port_80_cnt";
    private static final String cm_ip_port_80_len   = "cm_ip_port_80_len";
    private static final String cm_ip_tcp_syn_cnt   = "cm_ip_tcp_syn_cnt";
    private static final String cm_ip_tcp_syn_len   = "cm_ip_tcp_syn_len";
    private static final String cm_ip_tcp_ack_cnt   = "cm_ip_tcp_ack_cnt";
    private static final String cm_ip_tcp_ack_len   = "cm_ip_tcp_ack_len";
    private static final String cm_ip_tcp_rst_cnt   = "cm_ip_tcp_rst_cnt";
    private static final String cm_ip_tcp_rst_len   = "cm_ip_tcp_rst_len";
    private static final String cm_ip_icmp_cnt      = "cm_ip_icmp_cnt";
    private static final String cm_ip_icmp_len      = "cm_ip_icmp_len";
    private static final String BM_IP_SRC           = "bm_ip_src";
    private static final String BM_IP_DST           = "bm_ip_dst";
    private static final String BM_IP_SRC_PORT_SRC  = "bm_ip_src_port_src";
    private static final String BM_IP_SRC_PORT_DST  = "bm_ip_src_port_dst";
    private static final String BM_IP_DST_PORT_SRC  = "bm_ip_dst_port_src";
    private static final String BM_IP_DST_PORT_DST  = "bm_ip_dst_port_dst";
    private static final int PORT_FIELD_BITWIDTH    = 9;

    private static final PiMatchFieldId INGRESS_PORT_ID = PiMatchFieldId.of(STANDARD_METADATA + DOT + "ingress_port");
    private static final PiMatchFieldId ETH_DST_ID      = PiMatchFieldId.of(HDR + DOT + ETHERNET + DOT + "dst_addr");
    private static final PiMatchFieldId ETH_SRC_ID      = PiMatchFieldId.of(HDR + DOT + ETHERNET + DOT + "src_addr");
    private static final PiMatchFieldId IPV4_SRC_ID     = PiMatchFieldId.of(HDR + DOT + IPV4 + DOT + "src_addr");
    private static final PiMatchFieldId IPV4_DST_ID     = PiMatchFieldId.of(HDR + DOT + IPV4 + DOT + "dst_addr");
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

    @SuppressWarnings("OptionalGetWithoutIsPresent")
    @Override
    public InboundPacket mapInboundPacket(PiPacketOperation packetIn, DeviceId deviceId) throws PiInterpreterException {
        
        // We assume that the packet is ethernet, which is fine since mytunnel.p4 can deparse only ethernet packets.
        Ethernet ethPkt;

        try {
            ethPkt = Ethernet.deserializer().deserialize(packetIn.data().asArray(), 0, packetIn.data().size());
        } catch (DeserializationException dex) {
            throw new PiInterpreterException(dex.getMessage());
        }

        // Retrieve the packet metadata fields from the received packet_in.

        Optional<PiPacketMetadata> packetMetadataIngress = packetIn.metadatas().stream()
                .filter(metadata -> metadata.id().toString().equals(INGRESS_PORT))
                .findFirst();

        Optional<PiPacketMetadata> packetMetadataIpSrc = packetIn.metadatas().stream()
                .filter(metadata -> metadata.id().toString().equals(IP_SRC))
                .findFirst();

        Optional<PiPacketMetadata> packetMetadataIpDst = packetIn.metadatas().stream()
                .filter(metadata -> metadata.id().toString().equals(IP_DST))
                .findFirst();

        // The packet_in metadata fields are retrieved as bytebuffers, converted, and saved as strings.

        ByteBuffer ipSrcBB = packetMetadataIpSrc.get().value().asReadOnlyBuffer();
        ByteBuffer ipDstBB = packetMetadataIpDst.get().value().asReadOnlyBuffer();

        // For the src/dst IP, we perform a sequence of conversions, bytebuffer -> int -> hex string -> byte array.
        // In order to obtain a final string composed by the IP octets.
        String ipSrcHex = decToHex(ipSrcBB.getInt());
        String ipDstHex = decToHex(ipDstBB.getInt());
        String ipSrcStr = null;
        String ipDstStr = null;
        try {
            ipSrcStr = InetAddress.getByAddress(hexStringToByteArray(ipSrcHex)).toString().split("/")[1];
            ipDstStr = InetAddress.getByAddress(hexStringToByteArray(ipDstHex)).toString().split("/")[1];
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }

        // If the IP src address is 0 or 10.0.0.1 (test ping), then the packet_in does not come from a threshold alert.
        // In that case, we skip the rest of the metadata processing and do not send anything to the ML pipeline.
        assert ipSrcStr != null;
        if ((!ipSrcStr.equals("0")) &&
            (!ipSrcStr.equals("0.0.0.0")) &&
            (!ipSrcStr.equals("10.0.0.1"))) {

            Optional<PiPacketMetadata> packetMetadataCmIpCnt = packetIn.metadatas().stream()
                    .filter(metadata -> metadata.id().toString().equals(cm_ip_cnt))
                    .findFirst();

            String cmIpCntStr = Integer.toString(packetMetadataCmIpCnt.get().value().asReadOnlyBuffer().getInt());

            Optional<PiPacketMetadata> packetMetadataCmIpLen = packetIn.metadatas().stream()
                    .filter(metadata -> metadata.id().toString().equals(cm_ip_len))
                    .findFirst();

            String cmIpLenStr = Integer.toString(packetMetadataCmIpLen.get().value().asReadOnlyBuffer().getInt());

            Optional<PiPacketMetadata> packetMetadataCmIpLenSS = packetIn.metadatas().stream()
                    .filter(metadata -> metadata.id().toString().equals(cm_ip_len_ss))
                    .findFirst();

            String cmIpLenSSStr = Long.toString(packetMetadataCmIpLenSS.get().value().asReadOnlyBuffer().getLong());

            Optional<PiPacketMetadata> packetMetadataCmIpPort21Cnt = packetIn.metadatas().stream()
                    .filter(metadata -> metadata.id().toString().equals(cm_ip_port_21_cnt))
                    .findFirst();

            String cmIpPort21CntStr = Integer.toString(packetMetadataCmIpPort21Cnt.get().value().asReadOnlyBuffer().getInt());

            Optional<PiPacketMetadata> packetMetadataCmIpPort21Len = packetIn.metadatas().stream()
                    .filter(metadata -> metadata.id().toString().equals(cm_ip_port_21_len))
                    .findFirst();

            String cmIpPort21LenStr = Integer.toString(packetMetadataCmIpPort21Len.get().value().asReadOnlyBuffer().getInt());

            Optional<PiPacketMetadata> packetMetadataCmIpPort22Cnt = packetIn.metadatas().stream()
                    .filter(metadata -> metadata.id().toString().equals(cm_ip_port_22_cnt))
                    .findFirst();

            String cmIpPort22CntStr = Integer.toString(packetMetadataCmIpPort22Cnt.get().value().asReadOnlyBuffer().getInt());

            Optional<PiPacketMetadata> packetMetadataCmIpPort22Len = packetIn.metadatas().stream()
                    .filter(metadata -> metadata.id().toString().equals(cm_ip_port_22_len))
                    .findFirst();

            String cmIpPort22LenStr = Integer.toString(packetMetadataCmIpPort22Len.get().value().asReadOnlyBuffer().getInt());

            Optional<PiPacketMetadata> packetMetadataCmIpPort80Cnt = packetIn.metadatas().stream()
                    .filter(metadata -> metadata.id().toString().equals(cm_ip_port_80_cnt))
                    .findFirst();

            String cmIpPort80CntStr = Integer.toString(packetMetadataCmIpPort80Cnt.get().value().asReadOnlyBuffer().getInt());

            Optional<PiPacketMetadata> packetMetadataCmIpPort80Len = packetIn.metadatas().stream()
                    .filter(metadata -> metadata.id().toString().equals(cm_ip_port_80_len))
                    .findFirst();

            String cmIpPort80LenStr = Integer.toString(packetMetadataCmIpPort80Len.get().value().asReadOnlyBuffer().getInt());

            Optional<PiPacketMetadata> packetMetadataCmIpTcpSynCnt = packetIn.metadatas().stream()
                    .filter(metadata -> metadata.id().toString().equals(cm_ip_tcp_syn_cnt))
                    .findFirst();

            String cmIpTcpSynCntStr = Integer.toString(packetMetadataCmIpTcpSynCnt.get().value().asReadOnlyBuffer().getInt());

            Optional<PiPacketMetadata> packetMetadataCmIpTcpSynLen = packetIn.metadatas().stream()
                    .filter(metadata -> metadata.id().toString().equals(cm_ip_tcp_syn_len))
                    .findFirst();

            String cmIpTcpSynLenStr = Integer.toString(packetMetadataCmIpTcpSynLen.get().value().asReadOnlyBuffer().getInt());

            Optional<PiPacketMetadata> packetMetadataCmIpTcpAckCnt = packetIn.metadatas().stream()
                    .filter(metadata -> metadata.id().toString().equals(cm_ip_tcp_ack_cnt))
                    .findFirst();

            String cmIpTcpAckCntStr = Integer.toString(packetMetadataCmIpTcpAckCnt.get().value().asReadOnlyBuffer().getInt());

            Optional<PiPacketMetadata> packetMetadataCmIpTcpAckLen = packetIn.metadatas().stream()
                    .filter(metadata -> metadata.id().toString().equals(cm_ip_tcp_ack_len))
                    .findFirst();

            String cmIpTcpAckLenStr = Integer.toString(packetMetadataCmIpTcpAckLen.get().value().asReadOnlyBuffer().getInt());

            Optional<PiPacketMetadata> packetMetadataCmIpTcpRstCnt = packetIn.metadatas().stream()
                    .filter(metadata -> metadata.id().toString().equals(cm_ip_tcp_rst_cnt))
                    .findFirst();

            String cmIpTcpRstCntStr = Integer.toString(packetMetadataCmIpTcpRstCnt.get().value().asReadOnlyBuffer().getInt());

            Optional<PiPacketMetadata> packetMetadataCmIpTcpRstLen = packetIn.metadatas().stream()
                    .filter(metadata -> metadata.id().toString().equals(cm_ip_tcp_rst_len))
                    .findFirst();

            String cmIpTcpRstLenStr = Integer.toString(packetMetadataCmIpTcpRstLen.get().value().asReadOnlyBuffer().getInt());

            Optional<PiPacketMetadata> packetMetadataCmIpIcmpCnt = packetIn.metadatas().stream()
                    .filter(metadata -> metadata.id().toString().equals(cm_ip_icmp_cnt))
                    .findFirst();

            String cmIpIcmpCntStr = Integer.toString(packetMetadataCmIpIcmpCnt.get().value().asReadOnlyBuffer().getInt());

            Optional<PiPacketMetadata> packetMetadataCmIpIcmpLen = packetIn.metadatas().stream()
                    .filter(metadata -> metadata.id().toString().equals(cm_ip_icmp_len))
                    .findFirst();

            String cmIpIcmpLenStr = Integer.toString(packetMetadataCmIpIcmpLen.get().value().asReadOnlyBuffer().getInt());

            Optional<PiPacketMetadata> packetMetadataBmIpSrc = packetIn.metadatas().stream()
                    .filter(metadata -> metadata.id().toString().equals(BM_IP_SRC))
                    .findFirst();

            String bmIpSrcStr = Integer.toString(packetMetadataBmIpSrc.get().value().asReadOnlyBuffer().getInt());

            Optional<PiPacketMetadata> packetMetadataBmIpDst = packetIn.metadatas().stream()
                    .filter(metadata -> metadata.id().toString().equals(BM_IP_DST))
                    .findFirst();

            String bmIpDstStr = Integer.toString(packetMetadataBmIpDst.get().value().asReadOnlyBuffer().getInt());

            Optional<PiPacketMetadata> packetMetadataBmIpSrcPortSrc = packetIn.metadatas().stream()
                    .filter(metadata -> metadata.id().toString().equals(BM_IP_SRC_PORT_SRC))
                    .findFirst();

            String bmIpSrcPortSrcStr = Integer.toString(packetMetadataBmIpSrcPortSrc.get().value().asReadOnlyBuffer().getInt());

            Optional<PiPacketMetadata> packetMetadataBmIpSrcPortDst = packetIn.metadatas().stream()
                    .filter(metadata -> metadata.id().toString().equals(BM_IP_SRC_PORT_DST))
                    .findFirst();

            String bmIpSrcPortDstStr = Integer.toString(packetMetadataBmIpSrcPortDst.get().value().asReadOnlyBuffer().getInt());

            Optional<PiPacketMetadata> packetMetadataBmIpDstPortSrc = packetIn.metadatas().stream()
                    .filter(metadata -> metadata.id().toString().equals(BM_IP_DST_PORT_SRC))
                    .findFirst();

            String bmIpDstPortSrcStr = Integer.toString(packetMetadataBmIpDstPortSrc.get().value().asReadOnlyBuffer().getInt());

            Optional<PiPacketMetadata> packetMetadataBmIpDstPortDst = packetIn.metadatas().stream()
                    .filter(metadata -> metadata.id().toString().equals(BM_IP_DST_PORT_DST))
                    .findFirst();

            String bmIpDstPortDstStr = Integer.toString(packetMetadataBmIpDstPortDst.get().value().asReadOnlyBuffer().getInt());

            // Calculate mean and std. deviation from the received packet length values.

            double cmIpLenMean    = Double.parseDouble(cmIpLenStr) / Double.parseDouble(cmIpCntStr);
            double cmIpLenStdDev = Math.sqrt(Math.abs(Double.parseDouble(cmIpLenSSStr) / Double.parseDouble(cmIpCntStr) -
                                                Math.pow(cmIpLenMean, 2)));

            String cmIpLenMeanStr = Double.toString(cmIpLenMean);
            String cmIpLenStdDevStr = Double.toString(cmIpLenStdDev);
            
            // Generate the final string to be sent.

            String dma =
                    "{\"ip_src\": \"" + ipSrcStr + "\" , " +
                    "\"ip_dst\": \"" + ipDstStr + "\" , " +
                    "\"cm_ip_cnt\": \"" + cmIpCntStr + "\" , " +
                    "\"cm_ip_len\": \"" + cmIpLenStr + "\" , " +
                    "\"cm_ip_len_ss\": \"" + cmIpLenSSStr + "\" , " +
                    "\"cm_ip_len_mean\": \"" + cmIpLenMeanStr + "\" , " +
                    "\"cm_ip_len_std_dev\": \"" + cmIpLenStdDevStr + "\" , " +
                    "\"cm_ip_port_21_cnt\": \"" + cmIpPort21CntStr + "\" , " +
                    "\"cm_ip_port_21_len\": \"" + cmIpPort21LenStr + "\" , " +
                    "\"cm_ip_port_22_cnt\": \"" + cmIpPort22CntStr + "\" , " +
                    "\"cm_ip_port_22_len\": \"" + cmIpPort22LenStr + "\" , " +
                    "\"cm_ip_port_80_cnt\": \"" + cmIpPort80CntStr + "\" , " +
                    "\"cm_ip_port_80_len\": \"" + cmIpPort80LenStr + "\" , " +
                    "\"cm_ip_tcp_syn_cnt\": \"" + cmIpTcpSynCntStr + "\" , " +
                    "\"cm_ip_tcp_syn_len\": \"" + cmIpTcpSynLenStr + "\" , " +
                    "\"cm_ip_tcp_ack_cnt\": \"" + cmIpTcpAckCntStr + "\" , " +
                    "\"cm_ip_tcp_ack_len\": \"" + cmIpTcpAckLenStr + "\" , " +
                    "\"cm_ip_tcp_rst_cnt\": \"" + cmIpTcpRstCntStr + "\" , " +
                    "\"cm_ip_tcp_rst_len\": \"" + cmIpTcpRstLenStr + "\" , " +
                    "\"cm_ip_icmp_cnt\": \"" + cmIpIcmpCntStr + "\" , " +
                    "\"cm_ip_icmp_len\": \"" + cmIpIcmpLenStr + "\" , " +
                    "\"bm_ip_src\": \"" + bmIpSrcStr + "\" , " +
                    "\"bm_ip_dst\": \"" + bmIpDstStr + "\" , " +
                    "\"bm_ip_src_port_src\": \"" + bmIpSrcPortSrcStr + "\" , " +
                    "\"bm_ip_src_port_dst\": \"" + bmIpSrcPortDstStr + "\" , " +
                    "\"bm_ip_dst_port_src\": \"" + bmIpDstPortSrcStr + "\" , " +
                    "\"bm_ip_dst_port_dst\": \"" + bmIpDstPortDstStr + "\"}";

            dmaPost(dma);
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

    // Method that converts a decimal to an hex string.
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

    // Method that converts an hex string to a byte array.
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    // Method that receives the final string with all the metadata fields and sends it to the ML pipeline via REST.
    public void dmaPost(String dma) {

        HttpURLConnection conn;
        DataOutputStream os;

        try {

            URL url = new URL("http://127.0.0.1:5000/task/"); //important to add the trailing slash after add

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