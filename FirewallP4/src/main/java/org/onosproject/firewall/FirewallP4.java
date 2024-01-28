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

import org.onlab.packet.*;
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
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
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

    // Define the interception criteria for IPv4 addresses
    PiCriterion intercept = PiCriterion.builder()
            .matchTernary(PiMatchFieldId.of("hdr.ethernet.ether_type"), Ethernet.TYPE_IPV4, 0xffff)
            .matchTernary(PiMatchFieldId.of("hdr.ipv4.protocol"), IPv4.PROTOCOL_ICMP, 0xff)
            .build();

    private final Set<FwRule> rules = new HashSet<>();

    private final String ALLOW = "allow";

    private final String DENY = "deny";

    public static class FwRule {
        private final Ip4Address src;

        public Ip4Address getSrc() {
            return src;
        }

        private final Ip4Address dst;

        public Ip4Address getDst() {
            return dst;
        }

        private final String service;

        public String getService() {
            return service;
        }

        private int port;

        public int getPort() {
            return port;
        }

        private DeviceId deviceId;

        public DeviceId getDeviceId() {
            return deviceId;
        }

        public FwRule(Ip4Address src, Ip4Address dst, String service, DeviceId deviceId, int port) {
            this.src = src;
            this.dst = dst;
            this.service = service;
            this.deviceId = deviceId;
            this.port = port;
        }

        public FwRule(Ip4Address src, Ip4Address dst, String service, DeviceId deviceId) {
            this.src = src;
            this.dst = dst;
            this.service = service;
            this.deviceId = deviceId;
        }

        @Override
        public String toString() {
            return src + " " + dst + "   " + service + "     " + port + "    " + deviceId;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            FwRule fwRule = (FwRule) o;
            return port == fwRule.port && Objects.equals(src, fwRule.src) && Objects.equals(dst, fwRule.dst) && Objects.equals(service, fwRule.service);
        }

        @Override
        public int hashCode() {
            return Objects.hash(src, dst, service, port);
        }
    }

    public Set<FwRule> getFwRules() {
        return rules;
    }

    public void showFwRules() {
        System.out.println("Source IP     Destination IP  Service  Port  Device");
        for (FwRule rule : rules) {
            System.out.println(rule);
        }
    }

    public void addFwRules(FwRule rule) {
        rules.add(rule);
        applyFlowRule(rule.getDeviceId(), rule.getSrc(), rule.getDst(), rule.getService(), DENY);
    }

    public void removeFwRules(FwRule rule) {
        rules.remove(rule);
        applyFlowRule(rule.getDeviceId(), rule.getSrc(), rule.getDst(), rule.getService(), ALLOW);
    }

    @Activate
    public void activate() {
        appId = coreService.registerApplication("org.onosproject.firewall",
                () -> log.info("Periscope down."));
        //rules.add(new FwRule(Ip4Address.valueOf("192.168.100.1"), Ip4Address.valueOf("192.168.100.3"), "PING"));
        //rules.add(new FwRule(Ip4Address.valueOf("192.168.100.3"), Ip4Address.valueOf("192.168.100.1"), "PING"));
        //rules.add(new FwRule(Ip4Address.valueOf("192.168.100.1"), Ip4Address.valueOf("192.168.100.4"), "PING"));
        log.info("Started");
        packetService.addProcessor(packetProcessor, PROCESS_PRIORITY);
        packetService.requestPackets(DefaultTrafficSelector.builder().matchPi(intercept).build(),
                PacketPriority.CONTROL, appId, Optional.empty());
    }

    @Deactivate
    public void deactivate() {
        packetService.removeProcessor(packetProcessor);
        flowRuleService.removeFlowRulesById(appId);
        log.info("Stopped");
    }

    // Indicates whether the specified packet corresponds to ICMP ping.
    private boolean isIcmpPing(Ethernet eth) {
        return eth.getEtherType() == Ethernet.TYPE_IPV4 &&
                ((IPv4) eth.getPayload()).getProtocol() == IPv4.PROTOCOL_ICMP;
    }

    private boolean isTCP(Ethernet eth) {
        return eth.getEtherType() == Ethernet.TYPE_IPV4 &&
                (((IPv4) eth.getPayload()).getProtocol() == IPv4.PROTOCOL_TCP);
    }

    private boolean isUDP(Ethernet eth) {
        return eth.getEtherType() == Ethernet.TYPE_IPV4 &&
                (((IPv4) eth.getPayload()).getProtocol() == IPv4.PROTOCOL_UDP);
    }

    private class PingPacketProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            Ethernet eth = context.inPacket().parsed();
            if (isIcmpPing(eth)) {
                log.info("TRAMA ETHERNET: {}", eth);
                IPv4 packet = (IPv4) eth.getPayload();
                Ip4Address source = Ip4Address.valueOf(packet.getSourceAddress());
                Ip4Address destination = Ip4Address.valueOf(packet.getDestinationAddress());
                log.info("Ping de {} a {}", source, destination);
            } else if (isTCP(eth)) {
                log.info("TRAMA ETHERNET: {}", eth);
                IPv4 packet = (IPv4) eth.getPayload();
                Ip4Address source = Ip4Address.valueOf(packet.getSourceAddress());
                Ip4Address destination = Ip4Address.valueOf(packet.getDestinationAddress());
                log.info("TCP de {} a {}", source, destination);
            } else if (isUDP(eth)) {
                log.info("TRAMA ETHERNET: {}", eth);
                IPv4 packet = (IPv4) eth.getPayload();
                Ip4Address source = Ip4Address.valueOf(packet.getSourceAddress());
                Ip4Address destination = Ip4Address.valueOf(packet.getDestinationAddress());
                log.info("UDP de {} a {}", source, destination);
            }
        }
    }

    private void applyFlowRule(DeviceId deviceId, Ip4Address srcIp, Ip4Address dstIp, String service, String policy) {
        PiCriterion match = null;
        switch(service.toUpperCase()) {
            case "PING":
                // Define the interception criteria for IPv4 addresses
                match = PiCriterion.builder()
                        .matchTernary(PiMatchFieldId.of("hdr.ethernet.ether_type"), Ethernet.TYPE_IPV4, 0xffff)
                        .matchTernary(PiMatchFieldId.of("hdr.ipv4.src_addr"), srcIp.toInt(),0xffffffff)
                        .matchTernary(PiMatchFieldId.of("hdr.ipv4.dst_addr"), dstIp.toInt(), 0xffffffff)
                        .matchTernary(PiMatchFieldId.of("hdr.ipv4.protocol"), IPv4.PROTOCOL_ICMP, 0xff)
                        .build();
                break;
            case "TCP":
                // Define the interception criteria for IPv4 addresses
                match = PiCriterion.builder()
                        .matchTernary(PiMatchFieldId.of("hdr.ethernet.ether_type"), Ethernet.TYPE_IPV4, 0xffff)
                        .matchTernary(PiMatchFieldId.of("hdr.ipv4.src_addr"), srcIp.toInt(), 0xffffffff)
                        .matchTernary(PiMatchFieldId.of("hdr.ipv4.dst_addr"), dstIp.toInt(), 0xffffffff)
                        .matchTernary(PiMatchFieldId.of("hdr.ipv4.protocol"), IPv4.PROTOCOL_TCP, 0xff)
                        .build();
                break;
            case "UDP":
                // Define the interception criteria for IPv4 addresses
                match = PiCriterion.builder()
                        .matchTernary(PiMatchFieldId.of("hdr.ethernet.ether_type"), Ethernet.TYPE_IPV4, 0xffff)
                        .matchTernary(PiMatchFieldId.of("hdr.ipv4.src_addr"), srcIp.toInt(), 0xffffffff)
                        .matchTernary(PiMatchFieldId.of("hdr.ipv4.dst_addr"), dstIp.toInt(), 0xffffffff)
                        .matchTernary(PiMatchFieldId.of("hdr.ipv4.protocol"), IPv4.PROTOCOL_UDP, 0xff)
                        .build();
                break;
            default:
        }

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

        if (policy.equals(DENY)) {
            // Apply the drop rule
            flowRuleService.applyFlowRules(dropRule);
        } else if (policy.equals(ALLOW)) {
            // Remove the drop rule
            flowRuleService.removeFlowRules(dropRule);
        }
    }
}
