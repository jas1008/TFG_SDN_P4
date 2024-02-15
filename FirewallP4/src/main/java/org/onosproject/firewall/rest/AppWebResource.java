/**
 * Class that implements the interaction between the REST API and the Firewall application.
 *
 * @author: Juan Abelairas Soto-Largo
 */

package org.onosproject.firewall.rest;

import com.fasterxml.jackson.databind.node.ObjectNode;

import org.onlab.packet.Ip4Address;

import org.onosproject.net.DeviceId;
import org.onosproject.rest.AbstractWebResource;
import org.onosproject.firewall.FirewallP4;
import org.onosproject.firewall.FirewallP4.FwRule;

import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Set;

@Path("Policies")
public class AppWebResource extends AbstractWebResource {
    private final Logger log = LoggerFactory.getLogger(FirewallP4.class);

    @GET
    @Path("Show Rules")
    @Produces({MediaType.TEXT_PLAIN, MediaType.APPLICATION_JSON})
    public Response getFwRules() {
        FirewallP4 firewallP4Service = get(FirewallP4.class);
        Set<FwRule> rules = firewallP4Service.getFwRules();

        //ObjectMapper mapper = new ObjectMapper();
        //ArrayNode rulesArray = mapper.createArrayNode();
        ObjectNode node = mapper().createObjectNode().put("Firewall rules", rules.toString());
        log.info("LIST OF RULES {}", rules.toString());
        //StringBuilder stringBuilder = new StringBuilder();
        //for (FwRule rule : rules) {
        //    stringBuilder.append(rule.toString()).append("\n"); // Append each rule with newline character
        //}
        //return Response.ok(stringBuilder.toString()).build(); // Return plain text with newline character
        // Devolver las reglas como parte de la respuesta HTTP
        //ObjectNode node = mapper().createObjectNode().put(" status", rulesList.toString());
        //String jsonString = rulesArray.toString(); // Convert ArrayNode to JSON string
        return ok(node).build();
    }

    @POST
    @Path("Add Rule/{Source}/{Destination}/{Protocol}/{Device}")
    @Consumes({MediaType.APPLICATION_JSON})
    @Produces({MediaType.APPLICATION_JSON})
    public Response addFwRule(
            @PathParam("Source") String srcIP,
            @PathParam("Destination") String dstIP,
            @PathParam("Protocol") String service,
            @PathParam("Device") String device) {
        FwRule newRule = new FirewallP4.FwRule(Ip4Address.valueOf(srcIP), Ip4Address.valueOf(dstIP),
                service, DeviceId.deviceId(device));
        FirewallP4 firewallP4Service = get(FirewallP4.class);
        firewallP4Service.addFwRules(newRule);
        ObjectNode node = mapper().createObjectNode().put(" status", "ok");
        return ok(node).build();
    }

    @DELETE
    @Path("Remove Rule/{Source}/{Destination}/{Protocol}/{Device}")
    @Consumes({MediaType.APPLICATION_JSON})
    @Produces({MediaType.APPLICATION_JSON})
    public Response removeFwRule(
            @PathParam("Source") String srcIP,
            @PathParam("Destination") String dstIP,
            @PathParam("Protocol") String service,
            @PathParam("Device") String device) {
        FwRule newRule = new FirewallP4.FwRule(Ip4Address.valueOf(srcIP), Ip4Address.valueOf(dstIP),
                service, DeviceId.deviceId(device));
        FirewallP4 firewallP4Service = get(FirewallP4.class);
        firewallP4Service.removeFwRules(newRule);
        ObjectNode node = mapper().createObjectNode().put(" status", "ok");
        return ok(node).build();
    }
}
