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
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
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
import org.onosproject.net.host.HostEvent;
import org.onosproject.net.host.HostListener;
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
import java.util.Map;
import org.onosproject.net.flow.criteria.Criterion.Type;
import org.onosproject.net.flow.criteria.IPCriterion;
import org.onosproject.net.flow.criteria.Criterion;
import org.onlab.packet.Ip4Address;
import org.onosproject.net.flow.criteria.EthCriterion;
import org.onosproject.net.flow.criteria.IPProtocolCriterion;
import org.onosproject.net.flow.criteria.TcpFlagsCriterion;
import org.onosproject.net.flow.criteria.UdpPortCriterion;
import org.onosproject.net.flow.criteria.TcpPortCriterion;

import java.util.Date;
import java.text.SimpleDateFormat;
import java.util.concurrent.ConcurrentHashMap;
import java.io.File;

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
    private static final int FLOW_TABLE_SIZE = 250;

    private final FlowRuleListener flowListener = new InternalFlowListener();

    private ApplicationId appId;

    private static final Logger log = getLogger(FlowStats.class);

    //--------------------------------------------------------------------------
    // ONOS services needed by this application.
    //--------------------------------------------------------------------------

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private TopologyService topologyService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
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

        String ethSrcString     = "";
        String ethDstString     = "";
        String ipSrcString      = "";
        String ipDstString      = "";  
        String ipProtocol       = "";
        String tcpSrcPort       = "";
        String tcpDstPort       = "";
        String udpSrcPort       = "";
        String udpDstPort       = "";

        Long flowPackets    = 0L;
        Long flowBytes      = 0L;

        FlowNew currentFlow = new FlowNew();

        try {
            ethSrcString    = ((EthCriterion) flowRule.selector().getCriterion(Type.ETH_SRC)).mac().toString();     
            ethDstString    = ((EthCriterion) flowRule.selector().getCriterion(Type.ETH_DST)).mac().toString(); 
            ipSrcString     = ((IPCriterion) flowRule.selector().getCriterion(Type.IPV4_SRC)).ip().address().toString();  
            ipDstString     = ((IPCriterion) flowRule.selector().getCriterion(Type.IPV4_DST)).ip().address().toString();
            ipProtocol      = Short.toString(((IPProtocolCriterion) flowRule.selector().getCriterion(Type.IP_PROTO)).protocol());
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
            flowRuleService.removeFlowRules(flowRule);
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

    Runnable runnable = () -> {
        try {
            String timeStamp = new SimpleDateFormat("yyyy-MM-dd-HH-mm-ss-SSS").format(new Date());
            String currentUsersHomeDir = System.getProperty("user.home");
            String otherFolder = currentUsersHomeDir + File.separator + "Documents" + File.separator + "flow-stats" + File.separator;
            java.nio.file.Path txtpath = Paths.get(otherFolder + timeStamp + ".txt");

            for (String setKey : flowNewMap.keySet()) {

                FlowNew tempFlow    = flowNewMap.get(setKey);

                String flowPacketsString   = tempFlow.getFlowPackets();
                String flowBytesString     = tempFlow.getFlowBytes();
                String ipSrcString         = tempFlow.getFlowSrcIP();
                String ipDstString         = tempFlow.getFlowDstIP();
                String ipProtocol          = tempFlow.getFlowIPProtocol();
                String srcPort  = "";
                String dstPort  = "";
                    
                if (ipProtocol.equals("17")) {
                    srcPort   = tempFlow.getFlowUdpSrcPort();
                    dstPort   = tempFlow.getFlowUdpDstPort();
                } else {
                    srcPort   = tempFlow.getFlowTcpSrcPort();
                    dstPort   = tempFlow.getFlowTcpDstPort();
                }                

                // Write to file

                String flowSketchTotal =    flowPacketsString + "," +
                                            flowBytesString + "," + 
                                            ipSrcString + "," +
                                            ipDstString + "," + 
                                            ipProtocol + "," +
                                            srcPort + "," +
                                            dstPort;

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