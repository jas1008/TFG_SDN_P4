package org.onosproject.firewall.cli;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onosproject.firewall.FirewallP4;
import org.onosproject.net.DeviceId;
import org.onlab.packet.Ip4Address;
import org.onosproject.cli.AbstractShellCommand;
import org.onosproject.firewall.FirewallP4.FwRule;

/**
 * Command to add a firewall rule in a device.
 */
@Service
@Command(scope = "onos", name = "add-Fw-Rules", description = "Adds firewall rules")
public class AddFirewallRules extends AbstractShellCommand {

    @Argument(index = 0, name = "src_ip", description = "Source IP of the rule", required = true)
    String srcIP = null;

    @Argument(index = 1, name = "dst_ip", description = "Destination IP of the rule", required = true)
    String dstIP = null;

    @Argument(index = 2, name = "service", description = "Service of the rule", required = true)
    String service = null;

    @Argument(index = 3, name = "device", description = "Device of the rule", required = true)
    String device = null;

    @Argument(index = 4, name = "port", description = "Port of the rule")
    int port = 0;

    @Override
    protected void doExecute() {
        FirewallP4 firewallP4Service = AbstractShellCommand.get(FirewallP4.class);
        if (port > 0) {
            FwRule newRule = new FirewallP4.FwRule(Ip4Address.valueOf(srcIP), Ip4Address.valueOf(dstIP),
                    service, DeviceId.deviceId(device), port);
            firewallP4Service.addFwRules(newRule);
        } else if (port == 0) {
            FwRule newRule = new FirewallP4.FwRule(Ip4Address.valueOf(srcIP), Ip4Address.valueOf(dstIP),
                    service, DeviceId.deviceId(device));
            firewallP4Service.addFwRules(newRule);
        } else {
            System.out.println("El puerto debe ser un entero mayor que 0");
        }

    }
}
