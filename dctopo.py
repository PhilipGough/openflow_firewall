"""Cloud Infrastructure Topolgy

Implementing a three-layer hierarchical topology

Seven switches total
1 at core, 2 at aggregation and 4 at the access layer

Eight hosts total
Each access layer switch has two connected hosts

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo


class MyTopo(Topo):
    "Three-layer topology example."

    def __init__(self):
        "Create custom topo."

        # Initialize topology
        Topo.__init__(self)

        host = []
        switch = []

        # Add hosts and switches
        for i in range(1, 9):
            ip = '10.0.0.' + str(i)
            host.append(self.addHost('h' + str(i), ip=ip))

        for j in range(1, 8):
            print j
            if j is 1:
                switchCode = 'c'
            elif j > 1 and j < 4:
                switchCode = 'a'
            else:
                switchCode = 'e'
            switch.append(self.addSwitch(switchCode + str(j)))

        counter = 0
        for i, item in enumerate(switch, start=0):
            if i is 0:
                self.addLink(switch[i], switch[i + 1])
                self.addLink(switch[i], switch[i + 2])
            elif i is 1 or i is 2:
                for j in range(3, 7):
                    self.addLink(switch[i], switch[j])
            else:
                self.addLink(switch[i], host[counter])
                self.addLink(switch[i], host[counter + 1])
                counter += 2


topos = {'mytopo': (lambda: MyTopo())}
