package org.onosproject.firewall;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onosproject.cli.AbstractShellCommand;

/**
 * Command to check the current firewall rules applied in the device.
 */
@Service
@Command(scope = "onos", name = "show-Fw-Rules",
        description = "shows the firewall rules applied")
public class FirewallRules extends AbstractShellCommand {

    @Override
    protected void doExecute() {
        FirewallP4 RulesService = AbstractShellCommand.get(FirewallP4.class);
        RulesService.showFwRules();
    }
}
