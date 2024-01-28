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
package org.onosproject.firewall.rest;

import com.fasterxml.jackson.databind.node.ObjectNode;

import org.onlab.packet.Ip4Address;
import org.onosproject.net.DeviceId;
import org.onosproject.rest.AbstractWebResource;

import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.*;

import org.onosproject.firewall.FirewallP4;
import org.onosproject.firewall.FirewallP4.FwRule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Sample web resource.
 */

@Path("store")
public class AppWebResource extends AbstractWebResource {
    private final Logger log = LoggerFactory.getLogger(FirewallP4.class);


    @GET
    @Path("showRules")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getFwRules() {
        FirewallP4 FirewallP4Service = get(FirewallP4.class);
        Set<FwRule> rules = FirewallP4Service.getFwRules();
        //ObjectMapper mapper = new ObjectMapper();
        //ArrayNode rulesArray = mapper.createArrayNode();
        ObjectNode node = mapper().createObjectNode().put("Firewall rules", rules.toString());
        log.info("LIST OF RULES {}", rules.toString());
        // Devolver las reglas como parte de la respuesta HTTP
        //ObjectNode node = mapper().createObjectNode().put(" status", rulesList.toString());
        //String jsonString = rulesArray.toString(); // Convert ArrayNode to JSON string
        return ok(node).build();
    }

    @POST
    @Path("addRule/{srcIp}/{dstIp}/{service}/{device}")
    @Consumes({MediaType.APPLICATION_JSON})
    @Produces({MediaType.APPLICATION_JSON})
    public Response addFwRule(
            @PathParam("srcIp") String srcIP,
            @PathParam("dstIp") String dstIP,
            @PathParam("service") String service,
            @PathParam("device") String device) {
        FwRule newRule = new FirewallP4.FwRule(Ip4Address.valueOf(srcIP), Ip4Address.valueOf(dstIP), service, DeviceId.deviceId(device));
        FirewallP4 FirewallP4Service = get(FirewallP4.class);
        FirewallP4Service.addFwRules(newRule);
        ObjectNode node = mapper().createObjectNode().put(" status", "ok");
        return ok(node).build();
    }

    @DELETE
    @Path("removeRule/{srcIp}/{dstIp}/{service}/{device}")
    @Consumes({MediaType.APPLICATION_JSON})
    @Produces({MediaType.APPLICATION_JSON})
    public Response removeFwRule(
            @PathParam("srcIp") String srcIP,
            @PathParam("dstIp") String dstIP,
            @PathParam("service") String service,
            @PathParam("device") String device) {
        FwRule newRule = new FirewallP4.FwRule(Ip4Address.valueOf(srcIP), Ip4Address.valueOf(dstIP), service, DeviceId.deviceId(device));
        FirewallP4 FirewallP4Service = get(FirewallP4.class);
        FirewallP4Service.removeFwRules(newRule);
        ObjectNode node = mapper().createObjectNode().put(" status", "ok");
        return ok(node).build();
    }
}
