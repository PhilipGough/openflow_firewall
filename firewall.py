import csv
import os
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import EthAddr, IPAddr

# Use pwd to get realtive path to the 'firewall.csv' file
csv_file_path = os.path.join(os.path.dirname(__file__), 'firewall.csv')
log = core.getLogger()
all_ports = of.OFPP_FLOOD


class Firewall(object):

    def __init__(self):
        self.csv_file = open(csv_file_path, 'rb')
        self.file_reader = csv.DictReader(self.csv_file, delimiter=',')
        self.firewall = self.parse_csv()

    """ Create a nested dictionary to store mapping for both
        ethernet and ip packets"""

    def parse_csv(self):
        firewall = {}
        firewall['ip'] = {}
        firewall['mac'] = {}
        for row in self.file_reader:
            if row['id'] == 'mac':
                firewall['mac'].update({row['src']: row['dst']})
            else:
                firewall['ip'].update({row['src']: row['dst']})
        return firewall


class Controller(object):

    def __init__(self):
        self.firewall = Firewall()
        # This table maps (switch,MAC-addr) pairs to the port on 'switch' at
        # which we last saw a packet *from* 'MAC-addr'.
        self.table = {}
        core.openflow.addListeners(self)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        print packet
        self.table[(event.connection, packet.src)] = event.port

        dst_port = self.table.get((event.connection, packet.dst))

        if dst_port is None:
            # We don't know where the destination is yet.  So, we'll just
            # send the packet out all ports (except the one it came in on!)
            # and hope the destination is out there somewhere. :)
            msg = of.ofp_packet_out(data=event.ofp)
            msg.actions.append(of.ofp_action_output(port=all_ports))
            event.connection.send(msg)
        else:
            # Since we know the switch ports for both the source and dest
            # MACs, we can install rules for both directions.
            msg = of.ofp_flow_mod()
            msg.match.dl_dst = packet.src
            msg.match.dl_src = packet.dst
            msg.actions.append(of.ofp_action_output(port=event.port))
            event.connection.send(msg)

            # This is the packet that just came in -- we want to
            # install the rule and also resend the packet.
            msg = of.ofp_flow_mod()
            msg.data = event.ofp  # Forward the incoming packet
            msg.match.dl_src = packet.src
            msg.match.dl_dst = packet.dst
            msg.actions.append(of.ofp_action_output(port=dst_port))
            event.connection.send(msg)

            log.debug("Installing %s <-> %s" % (packet.src, packet.dst))

    """ Switch has now made an initial conn to the POX controller.
        At this point, we need to update the flows for this switch."""

    def _handle_ConnectionUp(self, event):
        firewall_table = self.firewall.firewall
        # Insert flows into switch with FlowMod and match on criteria
        for key, value in firewall_table.iteritems():
            if isinstance(value, dict):
                for src, dst in value.iteritems():
                    if key is 'mac':
                        # Add Flows both way to block this on switch conn
                        self.add_ethernet_rule(event.connection, src, dst)
                        self.add_ethernet_rule(event.connection, dst, src)

                    if key is 'ip':
                        # Match on IP type field in frame
                        msg = of.ofp_flow_mod()
                        msg.match.dl_type = 0x800
                        msg.match.nw_src = IPAddr(src)
                        msg.match.nw_dst = IPAddr(dst)
                        event.connection.send(msg)

    """ Build FlowMod rule for switch flow and send
        it out to the switch the connection came in on"""

    def add_ethernet_rule(self, conn, src, dst):
        msg = of.ofp_flow_mod()
        msg.match.dl_src = EthAddr(src)
        msg.match.dl_dst = EthAddr(dst)
        conn.send(msg)


def launch():
    # Create a Controller object when this component is launched
    core.registerNew(Controller)
