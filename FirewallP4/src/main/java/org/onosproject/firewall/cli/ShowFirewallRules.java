package org.onosproject.firewall.cli;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onosproject.cli.AbstractShellCommand;
import org.onosproject.firewall.FirewallP4;

/**
 * Command to check the current firewall rules applied in the device.
 */
@Service
@Command(scope = "onos", name = "show-Fw-Rules", description = "Shows the current firewall rules")
public class ShowFirewallRules extends AbstractShellCommand {

    @Override
    protected void doExecute() {
        FirewallP4 firewallP4Service = AbstractShellCommand.get(FirewallP4.class);
        firewallP4Service.showFwRules();
    }
}
