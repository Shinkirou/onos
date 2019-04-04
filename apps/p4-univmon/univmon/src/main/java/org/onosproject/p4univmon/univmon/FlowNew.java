package org.onosproject.p4univmon.univmon;

import org.onosproject.net.flow.FlowRule;

public class FlowNew {
	
	public Long 	flowPackets = 0L;
	public String 	flowBytes = "0";
	public String 	flowSrcIP;
	public String 	flowDstIP;
	public String 	flowIPProtocol;
	public String 	flowTcpSrcPort;
	public String 	flowTcpDstPort;
	public String 	flowUdpSrcPort;
	public String 	flowUdpDstPort;
	public FlowRule flowRule;

	public void setFlowPackets(Long flowPackets) {
		this.flowPackets = flowPackets;
	}

	public Long getFlowPackets() {
		return this.flowPackets;
	}

	public void addFlowPackets(Long flowPackets) {
		this.flowPackets += flowPackets;
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
}