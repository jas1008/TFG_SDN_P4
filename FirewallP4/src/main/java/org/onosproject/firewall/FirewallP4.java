/*
 * Copyright 2023-present Open Networking Foundation
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
package org.onosproject.firewall;

import com.google.common.base.Strings;
import org.onlab.packet.*;
import org.onlab.util.ImmutableByteSequence;
import org.onlab.util.Tools;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.host.HostProbingService;
import org.onosproject.net.host.HostService;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.pi.model.PiActionId;
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.model.PiTableId;
import org.onosproject.net.pi.runtime.PiAction;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * Skeletal ONOS application component.
 */
@Component(
        immediate = true,
        service = FirewallP4.class
        )

public class FirewallP4 {

    private final Logger log = LoggerFactory.getLogger(FirewallP4.class);

    private static final int PROCESS_PRIORITY = 128;

    private static final int DROP_PRIORITY = 50000;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostProbingService hostProbingService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowObjectiveService flowObjectiveService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;

    private ApplicationId appId;

    private final PacketProcessor packetProcessor = new PingPacketProcessor();

    PiCriterion intercept = PiCriterion.builder()
            .matchTernary(PiMatchFieldId.of("hdr.ethernet.ether_type"), Ethernet.TYPE_IPV4, 0xffff)
            .matchTernary(PiMatchFieldId.of("hdr.ipv4.protocol"), IPv4.PROTOCOL_ICMP, 0xff)
            .build();

    private final Set<FwRule> rules = new HashSet<>();

    private class FwRule {
        private final Ip4Address src;

        public Ip4Address getSrc() {
            return src;
        }

        private final Ip4Address dst;

        public Ip4Address getDst() {
            return dst;
        }

        public FwRule(Ip4Address src, Ip4Address dst) {
            this.src = src;
            this.dst = dst;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            FwRule fwRule = (FwRule) o;
            return Objects.equals(src, fwRule.src) && Objects.equals(dst, fwRule.dst);
        }

        @Override
        public int hashCode() {
            return Objects.hash(src, dst);
        }

        @Override
        public String toString() {
            return "FwRule{" +
                    "src=" + src +
                    ", dst=" + dst +
                    '}';
        }
    }

    public void showFwRules() {
        System.out.println("Reglas: " + rules);
    }

    @Activate
    public void activate(ComponentContext context) throws ImmutableByteSequence.ByteSequenceTrimException {
        appId = coreService.registerApplication("org.onosproject.firewall",
                () -> log.info("Periscope down."));
        rules.add(new FwRule(Ip4Address.valueOf("192.168.100.1"), Ip4Address.valueOf("192.168.100.3")));
        rules.add(new FwRule(Ip4Address.valueOf("192.168.100.3"), Ip4Address.valueOf("192.168.100.1")));
        rules.add(new FwRule(Ip4Address.valueOf("192.168.100.1"), Ip4Address.valueOf("192.168.100.4")));
        log.info("Started");
        log.warn("ESTOY EN ACTIVATE");
        for (FwRule rule : rules) {
            log.warn("Regla de firewall inicial: {}", rule);
        }
        packetService.addProcessor(packetProcessor, PROCESS_PRIORITY);
        packetService.requestPackets(DefaultTrafficSelector.builder().matchPi(intercept).build(),
                PacketPriority.CONTROL, appId, Optional.empty());
        //cfgService.registerProperties(getClass());
        //modified(context);
    }

    @Deactivate
    public void deactivate() {
        packetService.removeProcessor(packetProcessor);
        flowRuleService.removeFlowRulesById(appId);
        //cfgService.unregisterProperties(getClass(), false);
        log.info("Stopped");
    }

    // Indicates whether the specified packet corresponds to ICMP ping.
    private boolean isIcmpPing(Ethernet eth) {
        return eth.getEtherType() == Ethernet.TYPE_IPV4 &&
                ((IPv4) eth.getPayload()).getProtocol() == IPv4.PROTOCOL_ICMP;
    }

    private boolean isTCPUDP(Ethernet eth) {
        return eth.getEtherType() == Ethernet.TYPE_IPV4 &&
                (((IPv4) eth.getPayload()).getProtocol() == IPv4.PROTOCOL_TCP || ((IPv4) eth.getPayload()).getProtocol() == IPv4.PROTOCOL_UDP);
    }

    private class PingPacketProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            Ethernet eth = context.inPacket().parsed();
            if (isIcmpPing(eth)) {
                processPing(context, eth);
            } else if (isTCPUDP(eth)) {
                processTCPUDP(context, eth);
            }
        }
    }

    // Processes the specified ICMP ping packet.
    private void processPing(PacketContext context, Ethernet eth) {
        log.info("ESTOY EN PROCESSPING");
        DeviceId deviceId = context.inPacket().receivedFrom().deviceId();
        MacAddress src = eth.getSourceMAC();
        MacAddress dst = eth.getDestinationMAC();
        IPacket payload = eth.getPayload();
        IPv4 packet = (IPv4) eth.getPayload();
        Ip4Address source = Ip4Address.valueOf(packet.getSourceAddress());
        Ip4Address destination = Ip4Address.valueOf(packet.getDestinationAddress());
        applyFirewallRules(deviceId);
        log.info("Ping de {} a {}", source, destination);
        for (FwRule rule : rules) {
            log.warn("Regla de firewall actual: {}", rule.toString());
        }
    }

    // Processes the specified ICMP ping packet.
    private void processTCPUDP(PacketContext context, Ethernet eth) {
        log.info("ESTOY EN PROCESSTCPUDP");
        DeviceId deviceId = context.inPacket().receivedFrom().deviceId();
        MacAddress src = eth.getSourceMAC();
        MacAddress dst = eth.getDestinationMAC();
        IPv4 packet = (IPv4) eth.getPayload();
        Ip4Address source = Ip4Address.valueOf(packet.getSourceAddress());
        Ip4Address destination = Ip4Address.valueOf(packet.getDestinationAddress());
        applyFirewallRules(deviceId);
        log.info("Ping de {} a {}", source, destination);
        for (FwRule rule : rules) {
            log.warn("Regla de firewall actual: {}", rule.toString());
        }
    }

    private void applyFirewallRules(DeviceId deviceId) {
        log.info("APLICO REGLAS DE FIREWALL");
        for (FwRule rule : rules) {
            blockPingByIP(deviceId, rule.getSrc(), rule.getDst());
            blockTcpUdpByIP(deviceId, rule.getSrc(), rule.getDst());
        }
    }

    private void blockPingByIP(DeviceId deviceId, Ip4Address srcIp, Ip4Address dstIp) {
        // Define the interception criteria for IPv4 addresses
        PiCriterion match = PiCriterion.builder()
                .matchTernary(PiMatchFieldId.of("hdr.ethernet.ether_type"), Ethernet.TYPE_IPV4, 0xffff)
                .matchTernary(PiMatchFieldId.of("hdr.ipv4.src_addr"), srcIp.toInt(), 0xffffffff)
                .matchTernary(PiMatchFieldId.of("hdr.ipv4.dst_addr"), dstIp.toInt(), 0xffffffff)
                .matchTernary(PiMatchFieldId.of("hdr.ipv4.protocol"), IPv4.PROTOCOL_ICMP, 0xff)
                .build();

        // Define the action to drop the traffic
        PiAction action = PiAction.builder()
                .withId(PiActionId.of("ingress.table0_control.drop"))
                .build();

        // Define the drop rule
        FlowRule dropRule = DefaultFlowRule.builder()
                .forDevice(deviceId).fromApp(appId).makePermanent().withPriority(DROP_PRIORITY)
                .forTable(PiTableId.of("ingress.table0_control.table0"))
                .withSelector(DefaultTrafficSelector.builder().matchPi(match).build())
                .withTreatment(DefaultTrafficTreatment.builder().piTableAction(action).build())
                .build();

        // Apply the drop rule
        flowRuleService.applyFlowRules(dropRule);
    }

    private void blockTcpUdpByIP(DeviceId deviceId, Ip4Address srcIp, Ip4Address dstIp) {
        // Define the criteria for TCP interception using PiCriterion
        PiCriterion tcpMatch = PiCriterion.builder()
                .matchTernary(PiMatchFieldId.of("hdr.ethernet.ether_type"), Ethernet.TYPE_IPV4, 0xffff)
                .matchTernary(PiMatchFieldId.of("hdr.ipv4.src_addr"), srcIp.toInt(), 0xffffffff)
                .matchTernary(PiMatchFieldId.of("hdr.ipv4.dst_addr"), dstIp.toInt(), 0xffffffff)
                .matchTernary(PiMatchFieldId.of("hdr.ipv4.protocol"), IPv4.PROTOCOL_TCP, 0xff)
                .build();

        // Define the action to drop TCP traffic using PiAction
        PiAction tcpAction = PiAction.builder()
                .withId(PiActionId.of("ingress.table0_control.drop"))
                .build();

        // Create a flow rule to drop TCP packets
        FlowRule dropTcpRule = DefaultFlowRule.builder()
                .forDevice(deviceId).fromApp(appId).makePermanent().withPriority(DROP_PRIORITY)
                .forTable(PiTableId.of("ingress.table0_control.table0"))
                .withSelector(DefaultTrafficSelector.builder().matchPi(tcpMatch).build())
                .withTreatment(DefaultTrafficTreatment.builder().piTableAction(tcpAction).build())
                .build();

        // Apply the drop rule for TCP packets using FlowRuleService
        flowRuleService.applyFlowRules(dropTcpRule);

        // Define the criteria for UDP interception using PiCriterion
        PiCriterion udpMatch = PiCriterion.builder()
                .matchTernary(PiMatchFieldId.of("hdr.ethernet.ether_type"), Ethernet.TYPE_IPV4, 0xffff)
                .matchTernary(PiMatchFieldId.of("hdr.ipv4.src_addr"), srcIp.toInt(), 0xffffffff)
                .matchTernary(PiMatchFieldId.of("hdr.ipv4.dst_addr"), dstIp.toInt(), 0xffffffff)
                .matchTernary(PiMatchFieldId.of("hdr.ipv4.protocol"), IPv4.PROTOCOL_UDP, 0xff)
                .build();

        // Define the action to drop UDP traffic using PiAction
        PiAction udpAction = PiAction.builder()
                .withId(PiActionId.of("ingress.table0_control.drop"))
                .build();

        // Create a flow rule to drop UDP packets
        FlowRule dropUdpRule = DefaultFlowRule.builder()
                .forDevice(deviceId).fromApp(appId).makePermanent().withPriority(DROP_PRIORITY)
                .forTable(PiTableId.of("ingress.table0_control.table0"))
                .withSelector(DefaultTrafficSelector.builder().matchPi(udpMatch).build())
                .withTreatment(DefaultTrafficTreatment.builder().piTableAction(udpAction).build())
                .build();

        // Apply the drop rule for UDP packets using FlowRuleService
        flowRuleService.applyFlowRules(dropUdpRule);
    }
}
