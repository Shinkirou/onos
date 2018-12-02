package org.onosproject.p4sketches.flowstats;

import org.onosproject.net.flow.FlowRule;

public class FlowNew {
	
	public String flowPackets = "0";
	public String flowBytes = "0";
	public String flowSrcIP;
	public String flowDstIP;
	public String flowIPProtocol;
	public String flowTcpFlags;
	public String flowTcpSrcPort;
	public String flowTcpDstPort;
	public String flowUdpSrcPort;
	public String flowUdpDstPort;
	public String cmHash;
	public String bmHash;
	public String cmSketch;
	public String bmSketch;
	public String flowStatsTotal;
	public Long flowCount = 0L;
	public FlowRule flowRule;

	public void setFlowPackets(String flowPackets) {
		this.flowPackets = flowPackets;
	}

	public String getFlowPackets() {
		return this.flowPackets;
	}

	public void setFlowBytes(String flowBytes) {
		this.flowBytes = flowBytes;
	}

	public String getFlowBytes() {
		return this.flowBytes;
	}

	public void setFlowSrcIP(String flowSrcIP) {
		this.flowSrcIP = flowSrcIP;
	}

	public String getFlowSrcIP() {
		return this.flowSrcIP;
	}

	public void setFlowDstIP(String flowDstIP) {
		this.flowDstIP = flowDstIP;
	}

	public String getFlowDstIP() {
		return this.flowDstIP;
	}

	public void setFlowIPProtocol(String flowIPProtocol) {
		this.flowIPProtocol = flowIPProtocol;
	}	

	public String getFlowIPProtocol() {
		return this.flowIPProtocol;
	}

	public void setFlowTcpFlags(String flowTcpFlags) {
		this.flowTcpFlags = flowTcpFlags;
	}	

	public String getFlowTcpFlags() {
		return this.flowTcpFlags;
	}

	public void setFlowTcpSrcPort(String flowTcpSrcPort) {
		this.flowTcpSrcPort = flowTcpSrcPort;
	}	

	public String getFlowTcpSrcPort() {
		return this.flowTcpSrcPort;
	}

	public void setFlowTcpDstPort(String flowTcpDstPort) {
		this.flowTcpDstPort = flowTcpDstPort;
	}	

	public String getFlowTcpDstPort() {
		return this.flowTcpDstPort;
	}

	public void setFlowUdpSrcPort(String flowUdpSrcPort) {
		this.flowUdpSrcPort = flowUdpSrcPort;
	}	

	public String getFlowUdpSrcPort() {
		return this.flowUdpSrcPort;
	}

	public void setFlowUdpDstPort(String flowUdpDstPort) {
		this.flowUdpDstPort = flowUdpDstPort;
	}	

	public String getFlowUdpDstPort() {
		return this.flowUdpDstPort;
	}			

	public void setCMHash(String cmHash) {
		this.cmHash = cmHash;
	}

	public String getCMHash() {
		return this.cmHash;
	}

	public void setBMHash(String bmHash) {
		this.bmHash = bmHash;
	}

	public String getBMHash() {
		return this.bmHash;
	}

	public void setCMSketch(String cmSketch) {
		this.cmSketch = cmSketch;
	}

	public String getCMSketch() {
		return this.cmSketch;
	}

	public void setBMSketch(String bmSketch) {
		this.bmSketch = bmSketch;
	}

	public String getBMSketch() {
		return this.bmSketch;
	}

	public void setFlowCount(Long flowCount) {
		this.flowCount = flowCount;
	}

	public Long getFlowCount() {
		return this.flowCount;
	}

	public void incrementFlowCount() {
		this.flowCount++;
	}

	public void setFlowRule(FlowRule flowRule) {
		this.flowRule = flowRule;
	}

	public FlowRule getFlowRule() {
		return this.flowRule;
	}

	public void setFlowStatsTotal(String flowStatsTotal) {
		this.flowStatsTotal = flowStatsTotal;
	}

	public String getFlowStatsTotal() {
		return this.flowStatsTotal;
	}
}