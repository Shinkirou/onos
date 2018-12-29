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

package org.onosproject.p4sketches.flowstats;

import com.google.common.collect.Lists;
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.onlab.packet.IpAddress;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Host;
import org.onosproject.net.Link;
import org.onosproject.net.Path;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.host.HostService;
import org.onosproject.net.pi.model.PiActionId;
import org.onosproject.net.pi.model.PiActionParamId;
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.model.PiTableId;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.onosproject.net.topology.Topology;
import org.onosproject.net.topology.TopologyService;
import org.slf4j.Logger;

import java.util.Collections;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.slf4j.LoggerFactory.getLogger;

import static org.onosproject.net.flow.FlowRuleEvent.Type.RULE_UPDATED;
import static org.onosproject.net.flow.FlowRuleEvent.Type.RULE_ADDED;
import java.nio.file.Paths;
import java.util.Arrays;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.io.IOException;
import org.onosproject.net.flow.FlowRuleListener;
import org.onosproject.net.flow.FlowRuleEvent;
import org.onosproject.net.flow.FlowEntry;
import java.sql.Timestamp;
import java.util.HashMap;
import java.util.Map;
import java.nio.channels.FileChannel;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import org.onosproject.net.flow.TrafficSelector;
import org.onlab.packet.IpAddress;
import org.onosproject.net.flow.criteria.Criterion.Type;
import org.onosproject.net.flow.criteria.IPCriterion;
import org.onosproject.net.flow.criteria.Criterion;
import org.onlab.packet.Ip4Address;
import org.onosproject.net.flow.criteria.EthCriterion;
import java.net.URI;
import java.util.ArrayList;
import java.util.concurrent.ExecutorService;
import org.onosproject.net.flow.criteria.IPProtocolCriterion;
import org.onosproject.net.flow.criteria.TcpFlagsCriterion;
import org.onosproject.net.flow.criteria.UdpPortCriterion;
import org.onosproject.net.flow.criteria.TcpPortCriterion;


import org.onosproject.p4sketches.pipeconf.PipelineInterpreterImpl;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.Date;
import java.text.SimpleDateFormat;
import java.util.concurrent.ConcurrentHashMap;

import java.util.zip.CRC32;
import javax.xml.bind.DatatypeConverter;
import java.math.BigInteger;
import java.util.zip.*;

import org.onosproject.p4sketches.flowstats.FlowNew;

@Component(immediate = true)
public class FlowStats {

    private static final String APP_NAME = "org.onosproject.p4sketches.flowstats";

    private static Map<String,FlowNew> flowNewMap = new ConcurrentHashMap<String,FlowNew>();

    // Minimum value for the flow count used in the space-saving algorithm.
    private static Long globalMinValue = 1L;

    // Default priority used for flow rules installed by this app.
    private static final int FLOW_RULE_PRIORITY = 100;

    // Size of the ONOS flow table.
    private static final int FLOW_TABLE_SIZE = 500;

    private final FlowRuleListener flowListener = new InternalFlowListener();

    private ApplicationId appId;

    private static final Logger log = getLogger(FlowStats.class);

    //--------------------------------------------------------------------------
    // ONOS services needed by this application.
    //--------------------------------------------------------------------------

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    private FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    private CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    private TopologyService topologyService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    private HostService hostService;

    //--------------------------------------------------------------------------
    //--------------------------------------------------------------------------

    @Activate
    public void activate() {
        // Register app and event listeners.
        log.info("Starting...");
        appId = coreService.registerApplication(APP_NAME);
        flowRuleService.addListener(flowListener);
        log.info("STARTED", appId.id());
    }

    @Deactivate
    public void deactivate() {
        // Remove listeners and clean-up flow rules.
        log.info("Stopping...");
        flowRuleService.removeListener(flowListener);
        flowRuleService.removeFlowRulesById(appId);
        log.info("STOPPED");
    }

    private void writeUpdatedFlow(FlowRule flowRule) {

        String ethSrcString = "";
        String ethDstString = "";
        String ipSrcString  = "";
        String ipDstString  = "";  
        String ipProtocol   = "";
        String tcpSrcPort   = "";
        String tcpDstPort   = "";
        String udpSrcPort   = "";
        String udpDstPort   = "";

        Long flowPackets = 0L;
        Long flowBytes = 0L;

        FlowNew currentFlow = new FlowNew();

        try {
            ethSrcString    = ((EthCriterion) flowRule.selector().getCriterion(Type.ETH_SRC)).mac().toString();     
            ethDstString    = ((EthCriterion) flowRule.selector().getCriterion(Type.ETH_DST)).mac().toString(); 
            ipSrcString     = ((IPCriterion) flowRule.selector().getCriterion(Type.IPV4_SRC)).ip().address().toString();  
            ipDstString     = ((IPCriterion) flowRule.selector().getCriterion(Type.IPV4_DST)).ip().address().toString();
            short s         = ((IPProtocolCriterion) flowRule.selector().getCriterion(Type.IP_PROTO)).protocol();
            ipProtocol      = Short.toString(s);
        } catch (NullPointerException e) {
            e.printStackTrace();
        }

        try {
            tcpSrcPort      = ((TcpPortCriterion) flowRule.selector().getCriterion(Type.TCP_SRC)).tcpPort().toString();
            tcpDstPort      = ((TcpPortCriterion) flowRule.selector().getCriterion(Type.TCP_DST)).tcpPort().toString();  
        } catch (NullPointerException e) {
            e.printStackTrace();
        }

        try {
            udpSrcPort      = ((UdpPortCriterion) flowRule.selector().getCriterion(Type.UDP_SRC)).udpPort().toString();
            udpDstPort      = ((UdpPortCriterion) flowRule.selector().getCriterion(Type.UDP_DST)).udpPort().toString();                     
        } catch (NullPointerException e) {
            e.printStackTrace();
        }

        if (ethSrcString.equals("") || ethDstString.equals("") || ipSrcString.equals("")  || ipDstString.equals("")) {
            return;
        }

        if ((ipSrcString.equals("10.0.0.1")) && (ipDstString.equals("10.0.0.2"))) {
            Thread threadWriteToFile = new Thread(runnable);
            threadWriteToFile.start();
            flowRuleService.removeFlowRules(flowRule);
            return;
        }

        if ((ipSrcString.equals("10.0.0.2")) && (ipDstString.equals("10.0.0.1"))) {
            return;
        }

        FlowEntry flowEntry = getFlowEntry(flowRule);

        try {
           flowPackets  = flowEntry.packets(); 
           flowBytes    = flowEntry.bytes();
        } catch (NullPointerException e) {
            e.printStackTrace();
            return;
        }

        String keyString = "";
        if (ipProtocol.equals("17")) {
            keyString = ipSrcString + ipDstString + ipProtocol + udpSrcPort + udpDstPort;
        } else {
            keyString = ipSrcString + ipDstString + ipProtocol + tcpSrcPort + tcpDstPort;
        }
        String flowPacketsString = Long.toString(flowPackets + 1L);
        String flowBytesString = Long.toString(flowBytes);
        
        if (flowNewMap.containsKey(keyString)) {
            currentFlow = flowNewMap.get(keyString);
        } else {
            currentFlow.setFlowSrcIP(ipSrcString);
            currentFlow.setFlowDstIP(ipDstString);
            currentFlow.setFlowRule(flowRule);
            currentFlow.setFlowIPProtocol(ipProtocol);
            if (ipProtocol.equals("17")) {
                currentFlow.setFlowUdpSrcPort(udpSrcPort);
                currentFlow.setFlowUdpDstPort(udpDstPort);
            } else {
                currentFlow.setFlowTcpSrcPort(tcpSrcPort);
                currentFlow.setFlowTcpDstPort(tcpDstPort);
            }
        }

        Long newPacketsLong = checkFlowUpdate(flowPackets, currentFlow);

        // Check if the flow update refers to new packets.         
        if (!newPacketsLong.equals(0L)) {
            
            // Remove flows, if the limit is exceeded.
            flowRemoval(flowPackets, newPacketsLong, keyString, currentFlow);

            currentFlow.setFlowPackets(flowPacketsString);
            currentFlow.setFlowBytes(flowBytesString);
            if (ipProtocol.equals("17")) {
                currentFlow.setFlowUdpSrcPort(udpSrcPort);
                currentFlow.setFlowUdpDstPort(udpDstPort);
            } else {
                currentFlow.setFlowTcpSrcPort(tcpSrcPort);
                currentFlow.setFlowTcpDstPort(tcpDstPort);
            }    

            // Generate the CM and BM sketch hash, if not done already.
            if (currentFlow.getBM1Hash() == null) {
                flowSketchHash(currentFlow);                  
            }
        } else {
            return;
        }
    }

    private Long checkFlowUpdate(Long flowPackets, FlowNew currentFlow) {

        Long flowPacketsLong = Long.parseLong(currentFlow.getFlowPackets());
        
        if ((flowPackets.equals(0L)) && (flowPacketsLong.equals(0L))) {
            return 1L;
        }

        Long flowPacketsIncr = flowPackets + 1L;

        if ((flowPacketsIncr).equals(flowPacketsLong)) {
            return 0L;
        } else {
            Long newPacketsLong = flowPacketsIncr - flowPacketsLong;
            if (newPacketsLong.compareTo(0L) < 0) {
                return 0L;
            }
            return newPacketsLong;
        }
    }

    private void flowRemoval(Long flowPackets, Long newPackets, String keyString, FlowNew currentFlow) {

        Long flowCountLong = currentFlow.getFlowCount();
        Long flowPacketsIncr = flowPackets + 1L;

        if (flowCountLong > 0L) {
            while ((flowCountLong.compareTo(flowPacketsIncr)) < 0) {
                flowCountLong++;
                currentFlow.incrementFlowCount();
            }
        } else {
            if (flowNewMap.size() < FLOW_TABLE_SIZE) {
                currentFlow.setFlowCount(newPackets);
                flowNewMap.put(keyString, currentFlow);
            } else {
                String minKey = getMax();
                FlowNew tempFlow = flowNewMap.get(minKey);
                FlowRule minFlowRule = tempFlow.getFlowRule();
                flowRuleService.removeFlowRules(minFlowRule);
                Long minFlowCount = tempFlow.getFlowCount();
                flowNewMap.remove(minKey);
                currentFlow.setFlowCount(minFlowCount + newPackets);
                flowNewMap.put(keyString, currentFlow);
            }
        }
    }

    private void flowSketchHash(FlowNew currentFlow) {

        String ipSrcString = currentFlow.getFlowSrcIP();
        String ipDstString = currentFlow.getFlowDstIP();

        int ipProtoInt = Integer.parseInt(currentFlow.getFlowIPProtocol());

        int srcPortInt = 0;
        int dstPortInt = 0;

        if (ipProtoInt == 6) {
            srcPortInt = Integer.parseInt(currentFlow.getFlowTcpSrcPort());
            dstPortInt = Integer.parseInt(currentFlow.getFlowTcpDstPort());
        } else {
            srcPortInt = Integer.parseInt(currentFlow.getFlowUdpSrcPort());
            dstPortInt = Integer.parseInt(currentFlow.getFlowUdpDstPort());            
        }

        int ipSrc1Int = 0;
        int ipSrc2Int = 0;
        int ipSrc3Int = 0;
        int ipSrc4Int = 0;

        int ipDst1Int = 0;
        int ipDst2Int = 0;
        int ipDst3Int = 0;
        int ipDst4Int = 0;

        Pattern ppSrc = Pattern.compile("\\d+");
        Matcher mSrc = ppSrc.matcher(ipSrcString);

        Pattern ppDst = Pattern.compile("\\d+");
        Matcher mDst = ppDst.matcher(ipDstString);                    

        int i = 0;
        int j = 0;            

        while (mSrc.find()) {
            if (i == 0) ipSrc1Int = Integer.parseInt(mSrc.group());
            if (i == 1) ipSrc2Int = Integer.parseInt(mSrc.group());
            if (i == 2) ipSrc3Int = Integer.parseInt(mSrc.group());
            if (i == 3) ipSrc4Int = Integer.parseInt(mSrc.group());
            i++;                        
        }

        while (mDst.find()) {
            if (j == 0) ipDst1Int = Integer.parseInt(mDst.group());
            if (j == 1) ipDst2Int = Integer.parseInt(mDst.group());
            if (j == 2) ipDst3Int = Integer.parseInt(mDst.group());
            if (j == 3) ipDst4Int = Integer.parseInt(mDst.group());
            j++;                        
        }

        String ipSrc1String = Integer.toHexString(ipSrc1Int);
        String ipSrc2String = Integer.toHexString(ipSrc2Int);
        String ipSrc3String = Integer.toHexString(ipSrc3Int);
        String ipSrc4String = Integer.toHexString(ipSrc4Int);

        String ipDst1String = Integer.toHexString(ipDst1Int);
        String ipDst2String = Integer.toHexString(ipDst2Int);
        String ipDst3String = Integer.toHexString(ipDst3Int);
        String ipDst4String = Integer.toHexString(ipDst4Int);

        String ipProtoString = Integer.toHexString(ipProtoInt);

        String srcPortString = Integer.toHexString(srcPortInt);
        String dstPortString = Integer.toHexString(dstPortInt);

        ipSrc1String = ("00" + ipSrc1String).substring(ipSrc1String.length());
        ipSrc2String = ("00" + ipSrc2String).substring(ipSrc2String.length());  
        ipSrc3String = ("00" + ipSrc3String).substring(ipSrc3String.length());  
        ipSrc4String = ("00" + ipSrc4String).substring(ipSrc4String.length());

        ipDst1String = ("00" + ipDst1String).substring(ipDst1String.length());   
        ipDst2String = ("00" + ipDst2String).substring(ipDst2String.length());  
        ipDst3String = ("00" + ipDst3String).substring(ipDst3String.length());  
        ipDst4String = ("00" + ipDst4String).substring(ipDst4String.length());

        ipProtoString = ("00000000" + ipProtoString).substring(ipProtoString.length());

        srcPortString = ("00000000" + srcPortString).substring(srcPortString.length());
        dstPortString = ("00000000" + dstPortString).substring(dstPortString.length());

        byte[] ipSrcByteArray = hexStringToByteArray(ipSrc1String + ipSrc2String + ipSrc3String + ipSrc4String);
        byte[] ipDstByteArray = hexStringToByteArray(ipDst1String + ipDst2String + ipDst3String + ipDst4String);

        byte[] ipProtoByteArray = hexStringToByteArray(ipProtoString);

        byte[] srcPortByteArray = hexStringToByteArray(srcPortString);
        byte[] dstPortByteArray = hexStringToByteArray(dstPortString);
            
        CRC32 ip5tupleCRC32 = new CRC32();
        ip5tupleCRC32.update(ipSrcByteArray);
        ip5tupleCRC32.update(ipDstByteArray);
        ip5tupleCRC32.update(ipProtoByteArray);
        ip5tupleCRC32.update(srcPortByteArray);
        ip5tupleCRC32.update(dstPortByteArray);
        long ip5tupleModulo = ip5tupleCRC32.getValue() % 65536L;

        String ip5tupleHashString = Long.toString(ip5tupleModulo);

        CRC32 ipSrcCRC32 = new CRC32();
        ipSrcCRC32.update(ipSrcByteArray);
        long ipSrcHashModulo = ipSrcCRC32.getValue() % 65536L;

        String ipSrcHashString = Long.toString(ipSrcHashModulo);

        CRC32 ipDstCRC32 = new CRC32();
        ipDstCRC32.update(ipDstByteArray);
        long ipDstHashModulo = ipDstCRC32.getValue() % 65536L;

        String ipDstHashString = Long.toString(ipDstHashModulo);        

        currentFlow.setCMHash(ip5tupleHashString);
        currentFlow.setBM1Hash(ipSrcHashString);
        currentFlow.setBM2Hash(ipDstHashString);
    }

    Runnable runnable = () -> {
        try {
            String timeStamp = new SimpleDateFormat("yyyy-MM-dd-HH-mm-ss-SSS").format(new Date());
            java.nio.file.Path txtpath = Paths.get("/home/shinkirou/Documents/thesis-flow-stats/flows-" + timeStamp + ".txt");

            for (String setKey : flowNewMap.keySet()) {

                FlowNew tempFlow    = flowNewMap.get(setKey);

                String flowPacketsString   = tempFlow.getFlowPackets();
                String flowBytesString     = tempFlow.getFlowBytes();
                String ipSrcString         = tempFlow.getFlowSrcIP();
                String ipDstString         = tempFlow.getFlowDstIP();
                String ipProtocol          = tempFlow.getFlowIPProtocol();
                String srcPort = "";
                String dstPort = "";
                    
                if (ipProtocol.equals("17")) {
                    srcPort   = tempFlow.getFlowUdpSrcPort();
                    dstPort   = tempFlow.getFlowUdpDstPort();
                } else {
                    srcPort   = tempFlow.getFlowTcpSrcPort();
                    dstPort   = tempFlow.getFlowTcpDstPort();
                }

                String cmHash = tempFlow.getCMHash();
                String bm1Hash = tempFlow.getBM1Hash();
                String bm2Hash = tempFlow.getBM2Hash();                    

                // Write to file

                String flowSketchTotal =    flowPacketsString + "," +
                                            flowBytesString + "," + 
                                            ipSrcString + "," +
                                            ipDstString + "," + 
                                            ipProtocol + "," +
                                            srcPort + "," +
                                            dstPort + "," +
                                            cmHash + "," +
                                            bm1Hash + "," +
                                            bm2Hash;

                Files.write(txtpath, Arrays.asList(flowSketchTotal), StandardCharsets.UTF_8,
                Files.exists(txtpath) ? StandardOpenOption.APPEND : StandardOpenOption.CREATE);                
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    };

    private FlowEntry getFlowEntry(FlowRule flowRule) {
        Iterable<FlowEntry> flowEntries =
                flowRuleService.getFlowEntries(flowRule.deviceId());

        if (flowEntries != null) {
            for (FlowEntry entry : flowEntries) {
                if (entry.exactMatch(flowRule)) {
                    return entry;
                }
            }
        }
        return null;
    }

    private byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                         + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    private String getMax() {
        
        String minKey = null;
        Long minValue = Long.MAX_VALUE;
        
        for (String key : flowNewMap.keySet()) {
            FlowNew tempFlow = flowNewMap.get(key);
            Long value = tempFlow.getFlowCount();
            if (value == globalMinValue) {
                minValue = value;
                minKey = key;
                return minKey;
            }
            if (value < minValue) {
                minValue = value;
                minKey = key;
            }
        }
        if (minValue > globalMinValue) {
            globalMinValue = minValue;
        }
        return minKey;
    }    

    private class InternalFlowListener implements FlowRuleListener {
        @Override
        public void event(FlowRuleEvent event) {
            FlowRule flowRule = event.subject();
            if ((event.type() == RULE_ADDED) || (event.type() == RULE_UPDATED)) {
                writeUpdatedFlow(flowRule);
            }
        }
    }
}