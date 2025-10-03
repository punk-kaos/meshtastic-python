"""Code for IP tunnel over a mesh

# Note python-pytuntap was too buggy
# using pip3 install pytap2
# make sure to "sudo setcap cap_net_admin+eip /usr/bin/python3.8" so python can access tun device without being root
# sudo ip tuntap del mode tun tun0
# sudo bin/run.sh --port /dev/ttyUSB0 --setch-shortfast
# sudo bin/run.sh --port /dev/ttyUSB0 --tunnel --debug
# ssh -Y root@192.168.10.151 (or dietpi), default password p
# ncat -e /bin/cat -k -u -l 1235
# ncat -u 10.115.64.152 1235
# ping -c 1 -W 20 10.115.64.152
# ping -i 30 -W 30 10.115.64.152

# FIXME: use a more optimal MTU
"""

import logging
import platform
import threading
import struct
import socket
import subprocess
import sys

try:
    import fcntl  # type: ignore[attr-defined]
    import ctypes
    import ctypes.util
except Exception:  # pragma: no cover - only present on non-Darwin platforms
    fcntl = None  # type: ignore[assignment]
    ctypes = None  # type: ignore[assignment]

from pubsub import pub # type: ignore[import-untyped]

try:
    from pytap2 import TapDevice  # Linux-only dependency
except Exception:  # pragma: no cover - allow import without pytap2 on macOS
    TapDevice = None  # type: ignore[assignment]

from meshtastic.protobuf import portnums_pb2
from meshtastic import mt_config
from meshtastic.util import ipstr, readnet_u16

logger = logging.getLogger(__name__)

def onTunnelReceive(packet, interface):  # pylint: disable=W0613
    """Callback for received tunneled messages from mesh."""
    logger.debug(f"in onTunnelReceive()")
    tunnelInstance = mt_config.tunnelInstance
    tunnelInstance.onReceive(packet)


class Tunnel:
    """A TUN based IP tunnel over meshtastic"""

    class TunnelError(Exception):
        """An exception class for general tunnel errors"""
        def __init__(self, message):
            self.message = message
            super().__init__(self.message)

    def __init__(self, iface, subnet: str="10.115", netmask: str="255.255.0.0") -> None:
        """
        Constructor

        iface is the already open MeshInterface instance
        subnet is used to construct our network number (normally 10.115.x.x)
        """

        if not iface:
            raise Tunnel.TunnelError("Tunnel() must have a interface")

        if not subnet:
            raise Tunnel.TunnelError("Tunnel() must have a subnet")

        if not netmask:
            raise Tunnel.TunnelError("Tunnel() must have a netmask")

        self.iface = iface
        self.subnetPrefix = subnet

        # Allow Linux and macOS (Darwin). Other platforms remain unsupported.
        if platform.system() not in ("Linux", "Darwin"):
            raise Tunnel.TunnelError(
                "Tunnel() can only be instantiated on Linux or macOS (Darwin)"
            )

        mt_config.tunnelInstance = self

        """A list of chatty UDP services we should never accidentally
        forward to our slow network"""
        self.udpBlacklist = {
            1900,  # SSDP
            5353,  # multicast DNS
            9001,  # Yggdrasil multicast discovery
            64512, # cjdns beacon
        }

        """A list of TCP services to block"""
        self.tcpBlacklist = {
            5900,  # VNC (Note: Only adding for testing purposes.)
        }

        """A list of protocols we ignore"""
        self.protocolBlacklist = {
            0x02,  # IGMP
            0x80,  # Service-Specific Connection-Oriented Protocol in a Multilink and Connectionless Environment
        }

        # A new non standard log level that is lower level than DEBUG
        self.LOG_TRACE = 5

        # TODO: check if root?
        logger.info(
            "Starting IP to mesh tunnel (you must be root for this *pre-alpha* "
            "feature to work).  Mesh members:"
        )

        pub.subscribe(onTunnelReceive, "meshtastic.receive.data.IP_TUNNEL_APP")
        myAddr = self._nodeNumToIp(self.iface.myInfo.my_node_num)

        if self.iface.nodes:
            for node in self.iface.nodes.values():
                nodeId = node["user"]["id"]
                ip = self._nodeNumToIp(node["num"])
                logger.info(f"Node { nodeId } has IP address { ip }")

        logger.debug("creating TUN device with MTU=200")
        # FIXME - figure out real max MTU, it should be 240 - the overhead bytes for SubPacket and Data
        self.tun = None
        if self.iface.noProto:
            logger.warning(
                f"Not creating a TapDevice() because it is disabled by noProto"
            )
        else:
            system = platform.system()
            if system == "Linux":
                if TapDevice is None:
                    raise Tunnel.TunnelError(
                        "pytap2 is required for Linux TUN/TAP support. Install with the 'tunnel' extra."
                    )
                # Try to create a TAP/TUN device. Some platforms may not accept a
                # custom name; fall back to default naming if needed.
                try:
                    self.tun = TapDevice(name="mesh")
                except Exception as ex:  # pylint: disable=broad-except
                    logger.warning(
                        "TapDevice(name='mesh') failed (%s), retrying with default name",
                        ex,
                    )
                    self.tun = TapDevice()

                self.tun.up()
                self.tun.ifconfig(address=myAddr, netmask=netmask, mtu=200)
            elif system == "Darwin":
                try:
                    self.tun = DarwinTunDevice()
                except OSError as ex:  # pylint: disable=broad-except
                    logger.error(
                        "Failed to create utun device: %s. If you are on a managed Mac or running security/VPN software, creating utun may be blocked. Try running as an admin user, outside sandboxed shells, and temporarily disable VPN/content filters.",
                        ex,
                    )
                    raise
                self.tun.up()
                try:
                    self.tun.ifconfig(address=myAddr, netmask=netmask, mtu=200)
                except Exception as ex:  # pylint: disable=broad-except
                    # Provide actionable guidance on macOS configuration failures
                    logger.error(
                        "Failed to configure utun device: %s. Try running with sudo.",
                        ex,
                    )
                    raise

        self._rxThread = None
        if self.iface.noProto:
            logger.warning(
                f"Not starting TUN reader because it is disabled by noProto"
            )
        else:
            logger.debug(f"starting TUN reader, our IP address is {myAddr}")
            self._rxThread = threading.Thread(
                target=self.__tunReader, args=(), daemon=True
            )
            self._rxThread.start()

    def onReceive(self, packet):
        """onReceive"""
        p = packet["decoded"]["payload"]
        if packet["from"] == self.iface.myInfo.my_node_num:
            logger.debug("Ignoring message we sent")
        else:
            logger.debug(f"Received mesh tunnel message type={type(p)} len={len(p)}")
            # we don't really need to check for filtering here (sender should have checked),
            # but this provides useful debug printing on types of packets received
            if not self.iface.noProto:
                if not self._shouldFilterPacket(p):
                    self.tun.write(p)

    def _shouldFilterPacket(self, p):
        """Given a packet, decode it and return true if it should be ignored"""
        protocol = p[8 + 1]
        srcaddr = p[12:16]
        destAddr = p[16:20]
        subheader = 20
        ignore = False  # Assume we will be forwarding the packet
        if protocol in self.protocolBlacklist:
            ignore = True
            logger.log(
                self.LOG_TRACE, f"Ignoring blacklisted protocol 0x{protocol:02x}"
            )
        elif protocol == 0x01:  # ICMP
            icmpType = p[20]
            icmpCode = p[21]
            checksum = p[22:24]
            # pylint: disable=line-too-long
            logger.debug(
                f"forwarding ICMP message src={ipstr(srcaddr)}, dest={ipstr(destAddr)}, type={icmpType}, code={icmpCode}, checksum={checksum}"
            )
            # reply to pings (swap src and dest but keep rest of packet unchanged)
            # pingback = p[:12]+p[16:20]+p[12:16]+p[20:]
            # tap.write(pingback)
        elif protocol == 0x11:  # UDP
            srcport = readnet_u16(p, subheader)
            destport = readnet_u16(p, subheader + 2)
            if destport in self.udpBlacklist:
                ignore = True
                logger.log(self.LOG_TRACE, f"ignoring blacklisted UDP port {destport}")
            else:
                logger.debug(f"forwarding udp srcport={srcport}, destport={destport}")
        elif protocol == 0x06:  # TCP
            srcport = readnet_u16(p, subheader)
            destport = readnet_u16(p, subheader + 2)
            if destport in self.tcpBlacklist:
                ignore = True
                logger.log(self.LOG_TRACE, f"ignoring blacklisted TCP port {destport}")
            else:
                logger.debug(f"forwarding tcp srcport={srcport}, destport={destport}")
        else:
            logger.warning(
                f"forwarding unexpected protocol 0x{protocol:02x}, "
                "src={ipstr(srcaddr)}, dest={ipstr(destAddr)}"
            )

        return ignore

    def __tunReader(self):
        tap = self.tun
        logger.debug("TUN reader running")
        while True:
            p = tap.read()
            # logger.debug(f"IP packet received on TUN interface, type={type(p)}")
            destAddr = p[16:20]

            if not self._shouldFilterPacket(p):
                self.sendPacket(destAddr, p)

    def _ipToNodeId(self, ipAddr):
        # We only consider the last 16 bits of the nodenum for IP address matching
        ipBits = ipAddr[2] * 256 + ipAddr[3]

        if ipBits == 0xFFFF:
            return "^all"

        for node in self.iface.nodes.values():
            nodeNum = node["num"] & 0xFFFF
            # logger.debug(f"Considering nodenum 0x{nodeNum:x} for ipBits 0x{ipBits:x}")
            if (nodeNum) == ipBits:
                return node["user"]["id"]
        return None

    def _nodeNumToIp(self, nodeNum):
        return f"{self.subnetPrefix}.{(nodeNum >> 8) & 0xff}.{nodeNum & 0xff}"

    def sendPacket(self, destAddr, p):
        """Forward the provided IP packet into the mesh"""
        nodeId = self._ipToNodeId(destAddr)
        if nodeId is not None:
            logger.debug(
                f"Forwarding packet bytelen={len(p)} dest={ipstr(destAddr)}, destNode={nodeId}"
            )
            self.iface.sendData(p, nodeId, portnums_pb2.IP_TUNNEL_APP, wantAck=False)
        else:
            logger.warning(
                f"Dropping packet because no node found for destIP={ipstr(destAddr)}"
            )

    def close(self):
        """Close"""
        self.tun.close()


class DarwinTunDevice:
    """Minimal utun wrapper for macOS that mimics the TapDevice API we need.

    Reads/writes L3 IPv4 packets. Packets are prefixed with a 4-byte
    address family header when sent/received.
    """

    UTUN_CONTROL_NAME = b"com.apple.net.utun_control"
    CTLIOCGINFO = 0xC0644E03  # _IOWR('N', 3, struct ctl_info)
    AF_SYS_CONTROL = 2
    UTUN_OPT_IFNAME = 2

    def __init__(self, name=None) -> None:
        if platform.system() != "Darwin":
            raise RuntimeError("DarwinTunDevice is only available on macOS")
        if fcntl is None or ctypes is None:
            raise RuntimeError("macOS utun support requires fcntl and ctypes modules")

        # Create a kernel control socket for utun
        try:
            self.sock = socket.socket(socket.AF_SYSTEM, socket.SOCK_DGRAM, socket.SYSPROTO_CONTROL)
        except AttributeError as ex:
            raise RuntimeError("Python build lacks AF_SYSTEM/SYSPROTO_CONTROL support") from ex

        # Resolve UTUN control id via CTLIOCGINFO ioctl
        buf = bytearray(struct.pack("I96s", 0, self.UTUN_CONTROL_NAME))
        fcntl.ioctl(self.sock.fileno(), self.CTLIOCGINFO, buf)
        ctl_id, _ = struct.unpack("I96s", bytes(buf))

        # Build sockaddr_ctl and connect using libc.connect
        class SockaddrCtl(ctypes.Structure):
            _fields_ = [
                ("sc_len", ctypes.c_ubyte),
                ("sc_family", ctypes.c_ubyte),
                ("ss_sysaddr", ctypes.c_uint16),
                ("sc_id", ctypes.c_uint32),
                ("sc_unit", ctypes.c_uint32),
                ("sc_reserved", ctypes.c_uint32 * 5),
            ]

        sac = SockaddrCtl()
        sac.sc_len = ctypes.sizeof(SockaddrCtl)
        sac.sc_family = socket.AF_SYSTEM
        sac.ss_sysaddr = ctypes.c_uint16(self.AF_SYS_CONTROL)  # type: ignore[assignment]
        sac.sc_id = ctl_id
        for i in range(5):
            sac.sc_reserved[i] = 0

        libc_name = ctypes.util.find_library("c")
        if not libc_name:
            raise RuntimeError("Unable to locate libc for utun connect")
        libc = ctypes.CDLL(libc_name, use_errno=True)
        libc.connect.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
        libc.connect.restype = ctypes.c_int
        # Try kernel-chosen unit first, then a few explicit units
        attempted_units = [0] + list(range(1, 9))
        last_err = 0
        for unit in attempted_units:
            sac.sc_unit = unit
            res = libc.connect(
                self.sock.fileno(), ctypes.byref(sac), ctypes.c_uint32(ctypes.sizeof(SockaddrCtl))
            )
            if res == 0:
                break
            last_err = ctypes.get_errno()
        if res != 0:
            self.sock.close()
            raise OSError(last_err, "utun connect failed")

        # Query assigned interface name
        ifname = self.sock.getsockopt(socket.SYSPROTO_CONTROL, self.UTUN_OPT_IFNAME, 128)
        self.name = ifname.split(b"\x00", 1)[0].decode("utf-8")
        logger.info("Created utun interface %s", self.name)

    def up(self) -> None:  # Keep API parity
        pass

    def ifconfig(self, address: str, netmask: str, mtu=None) -> None:
        # Configure utun as point-to-point (expected on macOS). We set the
        # same local/peer IP, then add a network route via this interface so
        # the full mesh subnet (e.g., 10.115/16) is routed through utun.
        cfg = ["ifconfig", self.name, "inet", address, address, "up"]
        if mtu:
            cfg += ["mtu", str(mtu)]
        subprocess.check_call(cfg)

        # Add a route for the subnet through this utun interface.
        try:
            import ipaddress  # lazy import

            net = ipaddress.IPv4Network(f"{address}/{netmask}", strict=False)
            net_addr = str(net.network_address)
            mask_str = str(net.netmask)
            # Delete any pre-existing route and then add.
            subprocess.call(["route", "-n", "delete", "-net", net_addr, "-netmask", mask_str])
            subprocess.check_call([
                "route", "-n", "add", "-net", net_addr, "-netmask", mask_str, "-interface", self.name
            ])
        except Exception as ex:  # pylint: disable=broad-except
            # Routing can still be managed manually if this fails.
            logger.warning(
                "Could not add route for %s/%s via %s: %s. You may need: sudo route -n add -net %s -netmask %s -interface %s",
                address,
                netmask,
                self.name,
                ex,
                net_addr if 'net_addr' in locals() else '10.115.0.0',
                mask_str if 'mask_str' in locals() else netmask,
                self.name,
            )

    def read(self) -> bytes:
        data = self.sock.recv(65535)
        if len(data) < 4:
            return b""
        # Strip 4-byte address family header
        return data[4:]

    def write(self, payload: bytes) -> int:
        header = struct.pack("!I", socket.AF_INET)
        return self.sock.send(header + payload)

    def close(self) -> None:
        try:
            self.sock.close()
        except Exception:  # pragma: no cover
            pass
