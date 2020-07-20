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
import org.osgi.service.component.annotations.Modified;
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

import static org.slf4j.LoggerFactory.getLogger;

import static org.onosproject.net.flow.FlowRuleEvent.Type.RULE_UPDATED;
import static org.onosproject.net.flow.FlowRuleEvent.Type.RULE_ADDED;
import org.onosproject.net.flow.FlowRuleListener;
import org.onosproject.net.flow.FlowRuleEvent;
import org.onosproject.net.flow.FlowEntry;
import java.util.Map;
import org.onosproject.net.flow.criteria.Criterion.Type;
import org.onosproject.net.flow.criteria.IPCriterion;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.EthCriterion;

import java.util.concurrent.ConcurrentHashMap;

import org.onosproject.cfg.ComponentConfigService;
import org.osgi.service.component.ComponentContext;
import java.util.Dictionary;
import org.onlab.util.Tools;

import static org.onosproject.p4flowstats.flowstats.OsgiPropertyConstants.FLOW_RULE_CM_SKETCH;
import static org.onosproject.p4flowstats.flowstats.OsgiPropertyConstants.FLOW_RULE_CM_SKETCH_DEFAULT;
import static org.onosproject.p4flowstats.flowstats.OsgiPropertyConstants.FLOW_RULE_BM_SKETCH;
import static org.onosproject.p4flowstats.flowstats.OsgiPropertyConstants.FLOW_RULE_BM_SKETCH_DEFAULT;
import static org.onosproject.p4flowstats.flowstats.OsgiPropertyConstants.FLOW_RULE_AMS_SKETCH;
import static org.onosproject.p4flowstats.flowstats.OsgiPropertyConstants.FLOW_RULE_AMS_SKETCH_DEFAULT;
import static org.onosproject.p4flowstats.flowstats.OsgiPropertyConstants.FLOW_RULE_MV_SKETCH;
import static org.onosproject.p4flowstats.flowstats.OsgiPropertyConstants.FLOW_RULE_MV_SKETCH_DEFAULT;

@Component(    
    immediate = true,
    service = FlowStats.class,
    property = {
        FLOW_RULE_CM_SKETCH  + ":Boolean=" + FLOW_RULE_CM_SKETCH_DEFAULT,
        FLOW_RULE_BM_SKETCH  + ":Boolean=" + FLOW_RULE_BM_SKETCH_DEFAULT,
        FLOW_RULE_AMS_SKETCH + ":Boolean=" + FLOW_RULE_AMS_SKETCH_DEFAULT,
        FLOW_RULE_MV_SKETCH  + ":Boolean=" + FLOW_RULE_MV_SKETCH_DEFAULT,
    }
)
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

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;    

    //--------------------------------------------------------------------------
    //--------------------------------------------------------------------------

    // Sketch flow rule variables.
    private boolean flowRuleCmSketch  = FLOW_RULE_CM_SKETCH_DEFAULT;
    private boolean flowRuleBmSketch  = FLOW_RULE_BM_SKETCH_DEFAULT;
    private boolean flowRuleAmsSketch = FLOW_RULE_AMS_SKETCH_DEFAULT;
    private boolean flowRuleMvSketch  = FLOW_RULE_MV_SKETCH_DEFAULT;

    @Activate
    public void activate(ComponentContext context) {
        // Register app and event listeners.
        log.info("Starting...");
        appId = coreService.registerApplication(APP_NAME);
        cfgService.registerProperties(getClass());
        flowRuleService.addListener(flowListener);
        readComponentConfiguration(context);
        log.info("STARTED", appId.id());
    }

    @Deactivate
    public void deactivate() {
        // Remove listeners and clean-up flow rules.
        log.info("Stopping...");
        cfgService.unregisterProperties(getClass(), false);
        flowRuleService.removeListener(flowListener);
        flowRuleService.removeFlowRulesById(appId);
        log.info("STOPPED");
    }

    @Modified
    public void modified(ComponentContext context) {
        readComponentConfiguration(context);
    }    

    /**
     * Extracts properties from the component configuration context.
     *
     * @param context the component context
     */
    private void readComponentConfiguration(ComponentContext context) {
        Dictionary<?, ?> properties = context.getProperties();

        Boolean flowRuleCmSketchEnabled = Tools.isPropertyEnabled(properties, FLOW_RULE_CM_SKETCH);
        if (flowRuleCmSketchEnabled == null) {
            log.info("Flow Rule: CM Sketch is not configured, " + "using current value of {}", flowRuleCmSketch);
        } else {
            flowRuleCmSketch = flowRuleCmSketchEnabled;
            if (flowRuleCmSketch == true) {
                // Hardcoded for now.
                insertSketchFlowRule(DeviceId.deviceId("device:bmv2:s1"), "c_ingress.t_cm");
            }
            log.info("Configured. Flow Rule: CM Sketch is {}", flowRuleCmSketch ? "enabled" : "disabled");
        }

        Boolean flowRuleBmSketchEnabled = Tools.isPropertyEnabled(properties, FLOW_RULE_BM_SKETCH);
        if (flowRuleBmSketchEnabled == null) {
            log.info("Flow Rule: BM Sketch is not configured, " + "using current value of {}", flowRuleBmSketch);
        } else {
            flowRuleBmSketch = flowRuleBmSketchEnabled;
            if (flowRuleBmSketch == true) {
                // Hardcoded for now.
                insertSketchFlowRule(DeviceId.deviceId("device:bmv2:s1"), "c_ingress.t_bm");
            }
            log.info("Configured. Flow Rule: BM Sketch is {}", flowRuleBmSketch ? "enabled" : "disabled");
        }

        Boolean flowRuleAmsSketchEnabled = Tools.isPropertyEnabled(properties, FLOW_RULE_AMS_SKETCH);
        if (flowRuleAmsSketchEnabled == null) {
            log.info("Flow Rule: AMS Sketch is not configured, " + "using current value of {}", flowRuleAmsSketch);
        } else {
            flowRuleAmsSketch = flowRuleAmsSketchEnabled;
            if (flowRuleAmsSketch == true) {
                // Hardcoded for now.
                insertSketchFlowRule(DeviceId.deviceId("device:bmv2:s1"), "c_ingress.t_ams");
            }
            log.info("Configured. Flow Rule: AMS Sketch is {}", flowRuleAmsSketch ? "enabled" : "disabled");
        }

        Boolean flowRuleMvSketchEnabled = Tools.isPropertyEnabled(properties, FLOW_RULE_MV_SKETCH);
        if (flowRuleMvSketchEnabled == null) {
            log.info("Flow Rule: MV Sketch is not configured, " + "using current value of {}", flowRuleMvSketch);
        } else {
            flowRuleMvSketch = flowRuleMvSketchEnabled;
            if (flowRuleMvSketch == true) {
                // Hardcoded for now.
                insertSketchFlowRule(DeviceId.deviceId("device:bmv2:s1"), "c_ingress.t_mv");
            }
            log.info("Configured. Flow Rule: MV Sketch is {}", flowRuleMvSketch ? "enabled" : "disabled");
        }                        
    }

    private void insertSketchFlowRule(DeviceId switchId, String tableId) {

        PiMatchFieldId etherTypeMatchFieldId = PiMatchFieldId.of("hdr.ethernet.ether_type");
        PiTableId forwardingTableId = PiTableId.of(tableId);

        // IPv4.
        byte[] matchExactBytes1 = {0x08, 0x00};

        PiCriterion match = PiCriterion.builder().matchExact(etherTypeMatchFieldId, matchExactBytes1).build();

        PiActionId actionId = PiActionId.of("c_ingress._drop");
        
        PiAction action = PiAction.builder()
                .withId(actionId)
                .build();

        log.info("Inserting INGRESS rule on switch {}: table={}, match={}, action={}",
                 switchId, forwardingTableId, match, action);

        insertPiFlowRule(switchId, forwardingTableId, match, action);
    }

    private void insertPiFlowRule(DeviceId switchId, PiTableId tableId, PiCriterion piCriterion, PiAction piAction) {
        
        FlowRule rule = DefaultFlowRule.builder()
                .forDevice(switchId)
                .forTable(tableId)
                .fromApp(appId)
                .withPriority(FLOW_RULE_PRIORITY)
                .makePermanent()
                .withSelector(DefaultTrafficSelector.builder().matchPi(piCriterion).build())
                .withTreatment(DefaultTrafficTreatment.builder().piTableAction(piAction).build())
                .build();
        
        flowRuleService.applyFlowRules(rule);
    }

    private void writeUpdatedFlow(FlowRule flowRule) {

        String ethSrcString = "";
        String ethDstString = "";
        String ipSrcString  = "";
        String ipDstString  = "";

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
            flowRuleService.removeFlowRules(flowRule);
            return;
        }

        if ((ipSrcString.equals("10.0.0.2")) && (ipDstString.equals("10.0.0.1"))) {
            flowRuleService.removeFlowRules(flowRule);
            return;
        }

        FlowEntry flowEntry = getFlowEntry(flowRule);

        Long flowPackets = flowEntry.packets() + 1;

        Long flowId = flowRule.id().value();

        // Compares the number of packets stored in the flow map with the current controller value.
        // checkFlowUpdate returns the number of new packets belonging to the flow.
        Long newFlowPackets = checkFlowUpdate(flowPackets, flowId);

        // Check if the flow update refers to new packets.         
        if (!newFlowPackets.equals(0L)) {
            
            // Update the current flow count.
            // Perform flow removal, if the limit is exceeded.
            flowCountUpdate(flowPackets, newFlowPackets, flowId, flowRule);

            flowPacketsMap.put(flowId, Long.toString(flowPackets));
            flowBytesMap.put(flowId, Long.toString(flowEntry.bytes()));

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