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

package org.onosproject.p4flowstats.flowstats;

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
import org.onosproject.net.flow.criteria.IcmpTypeCriterion;
import org.onosproject.net.flow.criteria.IcmpCodeCriterion;

import java.util.Date;
import java.text.SimpleDateFormat;
import java.util.concurrent.ConcurrentHashMap;
import java.io.File;

@Component(immediate = true)
public class FlowStats {

    private static final String APP_NAME = "org.onosproject.p4flowstats.flowstats";

    private static Map<Long,String> flowPacketsMap  = new ConcurrentHashMap<Long,String>();
    private static Map<Long,String> flowBytesMap    = new ConcurrentHashMap<Long,String>();

    // Aux structs for the space-saving algorithm flow count. 
    private static Long globalMinFlowCount = 1L;
    private static Map<Long,Long> flowCountMap    = new ConcurrentHashMap<Long,Long>();
    private static Map<Long,FlowRule> flowRuleMap = new ConcurrentHashMap<Long,FlowRule>();

    // Default priority used for flow rules installed by this app.
    private static final int FLOW_RULE_PRIORITY = 100;

    // Size of the ONOS flow table.
    private static final int FLOW_TABLE_SIZE = 1000;

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

        try {
            ethSrcString = ((EthCriterion) flowRule.selector().getCriterion(Type.ETH_SRC)).mac().toString();     
            ethDstString = ((EthCriterion) flowRule.selector().getCriterion(Type.ETH_DST)).mac().toString(); 
            ipSrcString  = ((IPCriterion) flowRule.selector().getCriterion(Type.IPV4_SRC)).ip().address().toString();  
            ipDstString  = ((IPCriterion) flowRule.selector().getCriterion(Type.IPV4_DST)).ip().address().toString();
        } catch (NullPointerException e) {
            e.printStackTrace();
        }                                        

        if (ethSrcString.equals("") || ethDstString.equals("") || ipSrcString.equals("")  || ipDstString.equals("")) {
            return;
        }

        if ((ipSrcString.equals("10.0.0.1")) && (ipDstString.equals("10.0.0.2"))) {
            // Thread threadWriteToFile = new Thread(runnable);
            // threadWriteToFile.start();
            flowRuleService.removeFlowRules(flowRule);
            return;
        }

        if ((ipSrcString.equals("10.0.0.2")) && (ipDstString.equals("10.0.0.1"))) {
            flowRuleService.removeFlowRules(flowRule);
            return;
        }

        FlowEntry flowEntry = getFlowEntry(flowRule);

        Long flowPackets       = flowEntry.packets() + 1;
        String flowPacketsString = Long.toString(flowPackets); 
        String flowBytesString   = Long.toString(flowEntry.bytes());

        Long flowId = flowRule.id().value();

        // Compares the number of packets stored in the flow map with the current controller value.
        // checkFlowUpdate returns the number of new packets belonging to the flow.
        Long newFlowPackets = checkFlowUpdate(flowPackets, flowId);

        // Check if the flow update refers to new packets.         
        if (!newFlowPackets.equals(0L)) {
            
            // Update the current flow count.
            // Perform flow removal, if the limit is exceeded.
            flowCountUpdate(flowPackets, newFlowPackets, flowId, flowRule);

            flowPacketsMap.put(flowId, flowPacketsString);
            flowBytesMap.put(flowId, flowBytesString);

        } else {
            return;
        }
    }

    private Long checkFlowUpdate(Long flowPackets, Long flowId) {

        Long flowPacketsOld = 0L;

        try {
            flowPacketsOld = Long.parseLong(flowPacketsMap.get(flowId));    
        } catch(NumberFormatException e) {
            e.printStackTrace();
            return 0L;
        }
        
        
        if ((flowPackets.equals(0L)) && (flowPacketsOld.equals(0L))) {
            return 1L;
        }

        Long flowPacketsIncr = flowPackets + 1L;

        if ((flowPacketsIncr).equals(flowPacketsOld)) {
            return 0L;
        } else {
            Long newFlowPackets = flowPacketsIncr - flowPacketsOld;
            if (newFlowPackets.compareTo(0L) < 0) {
                return 0L;
            }
            return newFlowPackets;
        }
    }

    private void flowCountUpdate(Long flowPackets, Long newFlowPackets, Long flowId, FlowRule flowRule) {

        Long flowCount = flowCountMap.get(flowId);
        Long flowPacketsIncr = flowPackets + 1L;

        if (flowCount > 0L) {
            while ((flowCount.compareTo(flowPacketsIncr)) < 0) {
                flowCount++;
            }
            flowCountMap.put(flowId, flowCount);
        } else {
            if (flowCountMap.size() < FLOW_TABLE_SIZE) {
                flowCountMap.put(flowId, newFlowPackets);
                flowRuleMap.putIfAbsent(flowId, flowRule);
            } else {

                Long minFlowCountKey = getMinFlowCount();
                FlowRule minFlowRule = flowRuleMap.get(minFlowCountKey);
                flowRuleService.removeFlowRules(minFlowRule);
                Long minFlowCount = flowCountMap.get(minFlowCountKey);
                flowCountMap.remove(minFlowCountKey);
                flowCountMap.put(flowId, minFlowCount + newFlowPackets);
                flowRuleMap.putIfAbsent(flowId, flowRule);
            }
        }
    }

    /*
    Runnable runnable = () -> {
        
        try {

            String timeStamp = new SimpleDateFormat("yyyy-MM-dd-HH-mm-ss-SSS").format(new Date());
            String homeDir = System.getProperty("user.home");
            String destFolder = homeDir + File.separator + "Documents" + File.separator + "flow-stats" + File.separator;
            java.nio.file.Path txtPath = Paths.get(destFolder + timeStamp + ".txt");

            for (Long key : flowCountMap.keySet()) {

                String flowPackets = flowPacketsMap.get(key);
                String flowBytes = flowBytesMap.get(key);
                String flowIpSrc = flowIpSrcMap.get(key);
                String flowIpDst = flowIpDstMap.get(key);
                String flowIpProto = flowIpProtoMap.get(key);
                
                String flowSrcPort  = "";
                String flowDstPort  = "";
                String flowIcmpType = "";
                String flowIcmpCode = "";

                if (flowIpProto.equals("17")) {
                    flowSrcPort = flowUdpSrcMap.get(key);
                    flowDstPort = flowUdpDstMap.get(key);
                } else if (flowIpProto.equals("6")) {
                    flowSrcPort = flowTcpSrcMap.get(key);
                    flowDstPort = flowTcpDstMap.get(key);
                } else if (flowIpProto.equals("1")) {
                    flowIcmpType = flowIcmpTypeMap.get(key);
                    flowIcmpCode = flowIcmpCodeMap.get(key);
                }

                // Write to file

                String flowStats =  flowPackets + "," +
                                    flowBytes + "," + 
                                    flowIpSrc + "," +
                                    flowIpDst + "," + 
                                    flowIpProto + "," +
                                    flowSrcPort + "," +
                                    flowDstPort + "," + 
                                    flowIcmpType + "," + 
                                    flowIcmpCode;

                Files.write(txtPath, Arrays.asList(flowStats), StandardCharsets.UTF_8,
                Files.exists(txtPath) ? StandardOpenOption.APPEND : StandardOpenOption.CREATE);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    };
    */

    private FlowEntry getFlowEntry(FlowRule flowRule) {
        
        Iterable<FlowEntry> flowEntries = flowRuleService.getFlowEntries(flowRule.deviceId());

        if (flowEntries != null) {
            for (FlowEntry entry : flowEntries) {
                if (entry.exactMatch(flowRule)) {
                    return entry;
                }
            }
        }
        return null;
    }

    private Long getMinFlowCount() {
        
        Long minFlowKey = 0L;
        Long minFlowCount = Long.MAX_VALUE;
        
        for (Long key : flowCountMap.keySet()) {
            Long flowCount = flowCountMap.get(key);
            if (flowCount == globalMinFlowCount) {
                minFlowCount = flowCount;
                minFlowKey = key;
                return minFlowKey;
            }
            if (flowCount < minFlowCount) {
                minFlowCount = flowCount;
                minFlowKey = key;
            }
        }
        if (minFlowCount > globalMinFlowCount) {
            globalMinFlowCount = minFlowCount;
        }
        return minFlowKey;
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