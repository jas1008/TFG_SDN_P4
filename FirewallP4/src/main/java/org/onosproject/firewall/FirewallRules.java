package org.onosproject.firewall;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onosproject.cli.AbstractShellCommand;
import org.apache.karaf.shell.api.action.Argument;
import org.onlab.packet.MacAddress;
import org.onlab.packet.VlanId;
import org.onosproject.firewall.FirewallP4;

/**
 * Command to check the current firewall rules applied in the device.
 */
@Service
@Command(scope = "onos", name = "show-Fw-Rules",
        description = "Shows the current firewall rules")
public class FirewallRules extends AbstractShellCommand {

    @Override
    protected void doExecute() {
        FirewallP4 FirewallP4Service = AbstractShellCommand.get(FirewallP4.class);
        FirewallP4Service.showFwRules();
    }
}
