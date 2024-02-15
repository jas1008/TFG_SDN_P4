package org.onosproject.firewall.cli;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onlab.packet.Ip4Address;
import org.onosproject.cli.AbstractShellCommand;
import org.onosproject.firewall.FirewallP4;
import org.onosproject.firewall.FirewallP4.FwRule;
import org.onosproject.net.DeviceId;

/**
 * Command to delete a firewall rule applied in a device.
 */
@Service
@Command(scope = "onos", name = "remove-Fw-Rules", description = "Removes firewall rules")
public class RemoveFirewallRules extends AbstractShellCommand {

    @Argument(index = 0, name = "src_ip", description = "Source IP of the rule", required = true)
    String srcIP = null;

    @Argument(index = 1, name = "dst_ip", description = "Destination IP of the rule", required = true)
    String dstIP = null;

    @Argument(index = 2, name = "service", description = "Service of the rule", required = true)
    String service = null;

    @Argument(index = 3, name = "device", description = "Device of the rule", required = true)
    String device = null;

    @Override
    protected void doExecute() {
        FirewallP4 firewallP4Service = AbstractShellCommand.get(FirewallP4.class);
        FwRule newRule = new FwRule(Ip4Address.valueOf(srcIP), Ip4Address.valueOf(dstIP),
                service, DeviceId.deviceId(device));
        firewallP4Service.removeFwRules(newRule);
    }
}
