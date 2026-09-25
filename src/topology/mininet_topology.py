"""Real Mininet/OVS topology for MedTrustEdge Phase 1B.

Imports are deliberately guarded so the rest of the project remains runnable on
systems without Mininet. This module must be executed as root on Linux/WSL.
"""
try:
    from mininet.net import Mininet
    from mininet.node import Host, OVSSwitch
    from mininet.link import TCLink
    from mininet.log import setLogLevel
    MININET_IMPORT_ERROR = None
except ImportError as error:  # pragma: no cover - expected on non-Linux development hosts
    MININET_IMPORT_ERROR = error
    Host = object  # Keeps this module importable for non-Mininet unit tests.


# Mininet derives a DPID from a canonical ``s<number>`` name. These descriptive
# switch names are intentionally retained, so each OVS bridge gets an explicit,
# portable 64-bit (16 hexadecimal digit) datapath ID instead.
SWITCH_DPIDS = {
    "swA_access": "0000000000000001",
    "swA_edge_fog": "0000000000000002",
    "swA_fog_cloud": "0000000000000003",
    "swB_access": "0000000000000004",
    "swB_edge_fog": "0000000000000005",
    "swB_fog_cloud": "0000000000000006",
    "sw_baseline_a": "0000000000000007",
    "sw_baseline_b": "0000000000000008",
}
SWITCH_ALIASES = {
    "swA_access": "swaacc",
    "swA_edge_fog": "swaef",
    "swA_fog_cloud": "swafc",
    "swB_access": "swbacc",
    "swB_edge_fog": "swbef",
    "swB_fog_cloud": "swbfc",
    "sw_baseline_a": "sbasea",
    "sw_baseline_b": "sbaseb",
}
# Largest port index assigned to each node by the topology below.  Mininet names
# interfaces as ``<node>-eth<port>``; these limits keep every generated name
# below Linux IFNAMSIZ (15 visible characters).
MAX_INTERFACE_PORTS = {
    "iotA1": 1, "iotA2": 1, "iotA3": 1, "iotB1": 1, "iotB2": 1, "iotB3": 1,
    "edgeA": 1, "edgeB": 1, "fogA": 1, "fogB": 1, "cloud1": 3,
    "swaacc": 4, "swaef": 2, "swafc": 2, "swbacc": 4,
    "swbef": 2, "swbfc": 2, "sbasea": 4, "sbaseb": 4,
}
EXPECTED_HOST_NAMES = frozenset((
    "iotA1", "iotA2", "iotA3", "iotB1", "iotB2", "iotB3",
    "edgeA", "edgeB", "fogA", "fogB", "cloud1",
))
DEVICE_SPECS = (
    ("iotA1", "10.1.1.11/24"), ("iotA2", "10.1.1.12/24"), ("iotA3", "10.1.1.13/24"),
    ("iotB1", "10.2.1.11/24"), ("iotB2", "10.2.1.12/24"), ("iotB3", "10.2.1.13/24"),
)
NODE_INTERFACE_ADDRESSES = {
    "edgeA": (("edgeA-eth0", "10.1.1.10/24"), ("edgeA-eth1", "10.1.2.10/24")),
    "fogA": (("fogA-eth0", "10.1.2.11/24"), ("fogA-eth1", "10.1.3.10/24")),
    "edgeB": (("edgeB-eth0", "10.2.1.10/24"), ("edgeB-eth1", "10.2.2.10/24")),
    "fogB": (("fogB-eth0", "10.2.2.11/24"), ("fogB-eth1", "10.2.3.10/24")),
    "cloud1": (("cloud1-eth0", "10.1.3.11/24"), ("cloud1-eth1", "10.2.3.11/24"),
               ("cloud1-eth2", "10.10.1.10/24"), ("cloud1-eth3", "10.10.2.10/24")),
}
MEASUREMENT_DESTINATIONS = {
    "edge": {"A": "10.1.1.10", "B": "10.2.1.10"},
    "fog": {"A": "10.1.2.11", "B": "10.2.2.11"},
    "cloud": {"A": "10.1.3.11", "B": "10.2.3.11"},
    "cloud_baseline": {"A": "10.10.1.10", "B": "10.10.2.10"},
}


class LinuxRouter(Host):
    """A forwarding host used for Edge and Fog network functions."""
    def config(self, **params):
        result = super().config(**params)
        self.cmd("sysctl -w net.ipv4.ip_forward=1")
        self.cmd("sysctl -w net.ipv4.conf.all.rp_filter=0")
        return result

    def terminate(self):
        self.cmd("sysctl -w net.ipv4.ip_forward=0")
        super().terminate()


def mininet_is_available() -> bool:
    return MININET_IMPORT_ERROR is None


def require_mininet() -> None:
    if not mininet_is_available():
        raise RuntimeError("Mininet is not installed. Run this backend in a Linux/WSL environment with Mininet and Open vSwitch.") from MININET_IMPORT_ERROR


def build_network():
    """Build but do not start the two-tenant topology.

    The routed path is IoMT -> Edge -> Fog -> Cloud. Separate direct baseline
    interfaces let the same synthetic IoMT hosts measure IoMT -> Cloud without
    overwriting or relabeling the routed-path measurements.
    """
    require_mininet()
    net = Mininet(controller=None, switch=OVSSwitch, link=TCLink, build=False, autoSetMacs=True)
    # Each named OVS switch defines one L2 segment. Tenant A/B data segments do
    # not interconnect; only their Fog routers meet at cloud transit.
    switches = {
        # With controller=None, standalone mode is required for normal OVS MAC
        # learning. Secure mode would install no forwarding flows and isolate
        # hosts that share an access segment.
        logical_name: net.addSwitch(SWITCH_ALIASES[logical_name], dpid=dpid, failMode="standalone")
        for logical_name, dpid in SWITCH_DPIDS.items()
    }
    devices = {}
    for name, address in DEVICE_SPECS:
        devices[name] = net.addHost(name, ip=address)
        tenant = "a" if name[3] == "A" else "b"
        net.addLink(devices[name], switches[f"sw{'A' if tenant == 'a' else 'B'}_access"], cls=TCLink, delay="2ms", bw=20)
        # Second interface is used solely by the cloud-only baseline.
        net.addLink(devices[name], switches[f"sw_baseline_{tenant}"], cls=TCLink, delay="45ms", bw=30)
    edgeA = net.addHost("edgeA", cls=LinuxRouter); edgeB = net.addHost("edgeB", cls=LinuxRouter)
    fogA = net.addHost("fogA", cls=LinuxRouter); fogB = net.addHost("fogB", cls=LinuxRouter)
    cloud = net.addHost("cloud1", cls=LinuxRouter)
    net.addLink(edgeA, switches["swA_access"], cls=TCLink, delay="2ms", bw=20)
    net.addLink(edgeA, switches["swA_edge_fog"], cls=TCLink, delay="8ms", bw=100)
    net.addLink(fogA, switches["swA_edge_fog"], cls=TCLink, delay="8ms", bw=100)
    net.addLink(fogA, switches["swA_fog_cloud"], cls=TCLink, delay="25ms", bw=200)
    net.addLink(cloud, switches["swA_fog_cloud"], cls=TCLink, delay="25ms", bw=200)
    net.addLink(edgeB, switches["swB_access"], cls=TCLink, delay="2ms", bw=20)
    net.addLink(edgeB, switches["swB_edge_fog"], cls=TCLink, delay="8ms", bw=100)
    net.addLink(fogB, switches["swB_edge_fog"], cls=TCLink, delay="8ms", bw=100)
    net.addLink(fogB, switches["swB_fog_cloud"], cls=TCLink, delay="25ms", bw=200)
    net.addLink(cloud, switches["swB_fog_cloud"], cls=TCLink, delay="25ms", bw=200)
    net.addLink(cloud, switches["sw_baseline_a"], cls=TCLink, delay="45ms", bw=30)
    net.addLink(cloud, switches["sw_baseline_b"], cls=TCLink, delay="45ms", bw=30)
    return net, devices


def configure_addresses(net):
    """Assign deterministic multi-interface addresses and static routes after start."""
    nodes = {node.name: node for node in net.hosts}
    for node, interfaces in NODE_INTERFACE_ADDRESSES.items():
        for interface, address in interfaces: nodes[node].setIP(address, intf=interface)
    for name, host in nodes.items():
        if name.startswith("iotA"): host.cmd("ip addr add 10.10.1." + str(10 + int(name[-1])) + "/24 dev " + name + "-eth1") ; host.cmd("ip route add default via 10.1.1.10")
        if name.startswith("iotB"): host.cmd("ip addr add 10.10.2." + str(10 + int(name[-1])) + "/24 dev " + name + "-eth1") ; host.cmd("ip route add default via 10.2.1.10")
    nodes["edgeA"].cmd("ip route add 10.1.3.0/24 via 10.1.2.11; ip route add 10.2.0.0/16 via 10.1.2.11")
    nodes["edgeB"].cmd("ip route add 10.2.3.0/24 via 10.2.2.11; ip route add 10.1.0.0/16 via 10.2.2.11")
    nodes["fogA"].cmd("ip route add 10.1.1.0/24 via 10.1.2.10")
    nodes["fogB"].cmd("ip route add 10.2.1.0/24 via 10.2.2.10")
    nodes["cloud1"].cmd("ip route add 10.1.1.0/24 via 10.1.3.10; ip route add 10.2.1.0/24 via 10.2.3.10")
    return nodes
