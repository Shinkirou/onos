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
	public String bm1Hash;
	public String bm2Hash;
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

	public void setBM1Hash(String bm1Hash) {
		this.bm1Hash = bm1Hash;
	}

	public String getBM1Hash() {
		return this.bm1Hash;
	}

	public void setBM2Hash(String bm2Hash) {
		this.bm2Hash = bm2Hash;
	}

	public String getBM2Hash() {
		return this.bm2Hash;
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