from enum import Enum
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO

class DnsPacket(KaitaiStruct):

    class ClassType(Enum):
        in_class = 1
        cs = 2
        ch = 3
        hs = 4

    class TypeType(Enum):
        a = 1
        ns = 2
        md = 3
        mf = 4
        cname = 5
        soe = 6
        mb = 7
        mg = 8
        mr = 9
        null = 10
        wks = 11
        ptr = 12
        hinfo = 13
        minfo = 14
        mx = 15
        txt = 16

    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.transaction_id = self._io.read_u2be()
        self.flags = self._root.PacketFlags(self._io, self, self._root)
        self.qdcount = self._io.read_u2be()
        self.ancount = self._io.read_u2be()
        self.nscount = self._io.read_u2be()
        self.arcount = self._io.read_u2be()
        self.queries = [None] * (self.qdcount)
        for i in range(self.qdcount):
            self.queries[i] = self._root.Query(self._io, self, self._root)

        self.answers = [None] * (self.ancount)
        for i in range(self.ancount):
            self.answers[i] = self._root.Answer(self._io, self, self._root)

    class PointerStruct(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.value = self._io.read_u1()

        @property
        def contents(self):
            if hasattr(self, '_m_contents'):
                return self._m_contents if hasattr(self, '_m_contents') else None

            io = self._root._io
            _pos = io.pos()
            io.seek(self.value)
            self._m_contents = self._root.DomainName(io, self, self._root)
            io.seek(_pos)
            return self._m_contents if hasattr(self, '_m_contents') else None


    class Label(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.length = self._io.read_u1()
            if self.is_pointer:
                self.pointer = self._root.PointerStruct(self._io, self, self._root)

            if not (self.is_pointer):
                self.name = (self._io.read_bytes(self.length)).decode(u"ASCII")


        @property
        def is_pointer(self):
            if hasattr(self, '_m_is_pointer'):
                return self._m_is_pointer if hasattr(self, '_m_is_pointer') else None

            self._m_is_pointer = self.length == 192
            return self._m_is_pointer if hasattr(self, '_m_is_pointer') else None


    class Query(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.name = self._root.DomainName(self._io, self, self._root)
            self.type = self._root.TypeType(self._io.read_u2be())
            self.query_class = self._root.ClassType(self._io.read_u2be())


    class DomainName(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.name = []
            i = 0
            while True:
                _ = self._root.Label(self._io, self, self._root)
                self.name.append(_)
                if  ((_.length == 0) or (_.length == 192)) :
                    break
                i += 1


    class Address(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.ip = [None] * (4)
            for i in range(4):
                self.ip[i] = self._io.read_u1()


    class Answer(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.name = self._root.DomainName(self._io, self, self._root)
            self.type = self._root.TypeType(self._io.read_u2be())
            self.answer_class = self._root.ClassType(self._io.read_u2be())
            self.ttl = self._io.read_s4be()
            self.rdlength = self._io.read_u2be()
            if self.type == self._root.TypeType.ptr:
                self.ptrdname = self._root.DomainName(self._io, self, self._root)

            if self.type == self._root.TypeType.a:
                self.address = self._root.Address(self._io, self, self._root)


    class PacketFlags(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.flag = self._io.read_u2be()

        @property
        def qr(self):
            if hasattr(self, '_m_qr'):
                return self._m_qr if hasattr(self, '_m_qr') else None

            self._m_qr = ((self.flag & 32768) >> 15)
            return self._m_qr if hasattr(self, '_m_qr') else None

        @property
        def ra(self):
            if hasattr(self, '_m_ra'):
                return self._m_ra if hasattr(self, '_m_ra') else None

            self._m_ra = ((self.flag & 128) >> 7)
            return self._m_ra if hasattr(self, '_m_ra') else None

        @property
        def tc(self):
            if hasattr(self, '_m_tc'):
                return self._m_tc if hasattr(self, '_m_tc') else None

            self._m_tc = ((self.flag & 512) >> 9)
            return self._m_tc if hasattr(self, '_m_tc') else None

        @property
        def rcode(self):
            if hasattr(self, '_m_rcode'):
                return self._m_rcode if hasattr(self, '_m_rcode') else None

            self._m_rcode = ((self.flag & 15) >> 0)
            return self._m_rcode if hasattr(self, '_m_rcode') else None

        @property
        def opcode(self):
            if hasattr(self, '_m_opcode'):
                return self._m_opcode if hasattr(self, '_m_opcode') else None

            self._m_opcode = ((self.flag & 30720) >> 11)
            return self._m_opcode if hasattr(self, '_m_opcode') else None

        @property
        def aa(self):
            if hasattr(self, '_m_aa'):
                return self._m_aa if hasattr(self, '_m_aa') else None

            self._m_aa = ((self.flag & 1024) >> 10)
            return self._m_aa if hasattr(self, '_m_aa') else None

        @property
        def z(self):
            if hasattr(self, '_m_z'):
                return self._m_z if hasattr(self, '_m_z') else None

            self._m_z = ((self.flag & 64) >> 6)
            return self._m_z if hasattr(self, '_m_z') else None

        @property
        def rd(self):
            if hasattr(self, '_m_rd'):
                return self._m_rd if hasattr(self, '_m_rd') else None

            self._m_rd = ((self.flag & 256) >> 8)
            return self._m_rd if hasattr(self, '_m_rd') else None

        @property
        def cd(self):
            if hasattr(self, '_m_cd'):
                return self._m_cd if hasattr(self, '_m_cd') else None

            self._m_cd = ((self.flag & 16) >> 4)
            return self._m_cd if hasattr(self, '_m_cd') else None

        @property
        def ad(self):
            if hasattr(self, '_m_ad'):
                return self._m_ad if hasattr(self, '_m_ad') else None

            self._m_ad = ((self.flag & 32) >> 5)
            return self._m_ad if hasattr(self, '_m_ad') else None

class UdpDatagram(KaitaiStruct):

    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.src_port = self._io.read_u2be()
        self.dst_port = self._io.read_u2be()
        self.length = self._io.read_u2be()
        self.checksum = self._io.read_u2be()
        self.body = self._io.read_bytes_full()

class IgmpPacket(KaitaiStruct):

    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._io.read_bytes(8)
        self.body = self._io.read_bytes_full()

class IcmpPacket(KaitaiStruct):

    class IcmpTypeEnum(Enum):
        echo_reply = 0
        destination_unreachable = 3
        source_quench = 4
        redirect = 5
        echo = 8
        time_exceeded = 11

    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._io.read_bytes(8)
        self.body = self._io.read_bytes_full()
        #self._read()

    def _read(self):
        self.icmp_type = self._root.IcmpTypeEnum(self._io.read_u1())
        if self.icmp_type == self._root.IcmpTypeEnum.destination_unreachable:
            self.destination_unreachable = self._root.DestinationUnreachableMsg(self._io, self, self._root)

        if self.icmp_type == self._root.IcmpTypeEnum.time_exceeded:
            self.time_exceeded = self._root.TimeExceededMsg(self._io, self, self._root)

        if  ((self.icmp_type == self._root.IcmpTypeEnum.echo) or (self.icmp_type == self._root.IcmpTypeEnum.echo_reply)) :
            self.echo = self._root.EchoMsg(self._io, self, self._root)


    class DestinationUnreachableMsg(KaitaiStruct):

        class DestinationUnreachableCode(Enum):
            net_unreachable = 0
            host_unreachable = 1
            protocol_unreachable = 2
            port_unreachable = 3
            fragmentation_needed_and_df_set = 4
            source_route_failed = 5
            dst_net_unkown = 6
            sdt_host_unkown = 7
            src_isolated = 8
            net_prohibited_by_admin = 9
            host_prohibited_by_admin = 10
            net_unreachable_for_tos = 11
            host_unreachable_for_tos = 12
            communication_prohibited_by_admin = 13
            host_precedence_violation = 14
            precedence_cuttoff_in_effect = 15
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.code = self._root.DestinationUnreachableMsg.DestinationUnreachableCode(self._io.read_u1())
            self.checksum = self._io.read_u2be()


    class TimeExceededMsg(KaitaiStruct):

        class TimeExceededCode(Enum):
            time_to_live_exceeded_in_transit = 0
            fragment_reassembly_time_exceeded = 1
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.code = self._root.TimeExceededMsg.TimeExceededCode(self._io.read_u1())
            self.checksum = self._io.read_u2be()


    class EchoMsg(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.code = self._io.ensure_fixed_contents(b"\x00")
            self.checksum = self._io.read_u2be()
            self.identifier = self._io.read_u2be()
            self.seq_num = self._io.read_u2be()
            self.data = self._io.read_bytes_full()

class TcpSegment(KaitaiStruct):
    """TCP is one of the core Internet protocols on transport layer (AKA
    OSI layer 4), providing stateful connections with error checking,
    guarantees of delivery, order of segments and avoidance of duplicate
    delivery.
    """
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.src_port = self._io.read_u2be()
        self.dst_port = self._io.read_u2be()
        self.seq_num = self._io.read_u4be()
        self.ack_num = self._io.read_u4be()
        self.b12 = self._io.read_u1()
        self.b13 = self._io.read_u1()
        self.window_size = self._io.read_u2be()
        self.checksum = self._io.read_u2be()
        self.urgent_pointer = self._io.read_u2be()
        self.body = self._io.read_bytes_full()

class ProtocolBody(KaitaiStruct):
    """Protocol body represents particular payload on transport level (OSI
    layer 4).

    Typically this payload in encapsulated into network level (OSI layer
    3) packet, which includes "protocol number" field that would be used
    to decide what's inside the payload and how to parse it. Thanks to
    IANA's standardization effort, multiple network level use the same
    IDs for these payloads named "protocol numbers".

    This is effectively a "router" type: it expects to get protocol
    number as a parameter, and then invokes relevant type parser based
    on that parameter.

    .. seealso::
       Source - http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
    """

    class ProtocolEnum(Enum):
        hopopt = 0
        icmp = 1
        igmp = 2
        ggp = 3
        ipv4 = 4
        st = 5
        tcp = 6
        cbt = 7
        egp = 8
        igp = 9
        bbn_rcc_mon = 10
        nvp_ii = 11
        pup = 12
        argus = 13
        emcon = 14
        xnet = 15
        chaos = 16
        udp = 17
        mux = 18
        dcn_meas = 19
        hmp = 20
        prm = 21
        xns_idp = 22
        trunk_1 = 23
        trunk_2 = 24
        leaf_1 = 25
        leaf_2 = 26
        rdp = 27
        irtp = 28
        iso_tp4 = 29
        netblt = 30
        mfe_nsp = 31
        merit_inp = 32
        dccp = 33
        x_3pc = 34
        idpr = 35
        xtp = 36
        ddp = 37
        idpr_cmtp = 38
        tp_plus_plus = 39
        il = 40
        ipv6 = 41
        sdrp = 42
        ipv6_route = 43
        ipv6_frag = 44
        idrp = 45
        rsvp = 46
        gre = 47
        dsr = 48
        bna = 49
        esp = 50
        ah = 51
        i_nlsp = 52
        swipe = 53
        narp = 54
        mobile = 55
        tlsp = 56
        skip = 57
        ipv6_icmp = 58
        ipv6_nonxt = 59
        ipv6_opts = 60
        any_host_internal_protocol = 61
        cftp = 62
        any_local_network = 63
        sat_expak = 64
        kryptolan = 65
        rvd = 66
        ippc = 67
        any_distributed_file_system = 68
        sat_mon = 69
        visa = 70
        ipcv = 71
        cpnx = 72
        cphb = 73
        wsn = 74
        pvp = 75
        br_sat_mon = 76
        sun_nd = 77
        wb_mon = 78
        wb_expak = 79
        iso_ip = 80
        vmtp = 81
        secure_vmtp = 82
        vines = 83
        ttp_or_iptm = 84
        nsfnet_igp = 85
        dgp = 86
        tcf = 87
        eigrp = 88
        ospfigp = 89
        sprite_rpc = 90
        larp = 91
        mtp = 92
        ax_25 = 93
        ipip = 94
        micp = 95
        scc_sp = 96
        etherip = 97
        encap = 98
        any_private_encryption_scheme = 99
        gmtp = 100
        ifmp = 101
        pnni = 102
        pim = 103
        aris = 104
        scps = 105
        qnx = 106
        a_n = 107
        ipcomp = 108
        snp = 109
        compaq_peer = 110
        ipx_in_ip = 111
        vrrp = 112
        pgm = 113
        any_0_hop = 114
        l2tp = 115
        ddx = 116
        iatp = 117
        stp = 118
        srp = 119
        uti = 120
        smp = 121
        sm = 122
        ptp = 123
        isis_over_ipv4 = 124
        fire = 125
        crtp = 126
        crudp = 127
        sscopmce = 128
        iplt = 129
        sps = 130
        pipe = 131
        sctp = 132
        fc = 133
        rsvp_e2e_ignore = 134
        mobility_header = 135
        udplite = 136
        mpls_in_ip = 137
        manet = 138
        hip = 139
        shim6 = 140
        wesp = 141
        rohc = 142
        reserved_255 = 255

    def __init__(self, protocol_num, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self.protocol_num = protocol_num
        self._read()

    def _read(self):
        _on = self.protocol
        if _on == self._root.ProtocolEnum.tcp:
            self.body = TcpSegment(self._io)
        elif _on == self._root.ProtocolEnum.ipv6_nonxt:
            self.body = self._root.NoNextHeader(self._io, self, self._root)
        elif _on == self._root.ProtocolEnum.icmp:
            self.body = IcmpPacket(self._io)
        elif _on == self._root.ProtocolEnum.udp:
            self.body = UdpDatagram(self._io)
        elif _on == self._root.ProtocolEnum.hopopt:
            self.body = self._root.OptionHopByHop(self._io, self, self._root)
        elif _on == self._root.ProtocolEnum.ipv6:
            self.body = Ipv6Packet(self._io)
        elif _on == self._root.ProtocolEnum.ipv4:
            self.body = Ipv4Packet(self._io)
        elif _on == self._root.ProtocolEnum.igmp:
            self.body = IgmpPacket(self._io)

    class NoNextHeader(KaitaiStruct):
        """Dummy type for IPv6 "no next header" type, which signifies end of headers chain."""

        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            pass

    class OptionHopByHop(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.next_header_type = self._io.read_u1()
            self.hdr_ext_len = self._io.read_u1()
            self.body = self._io.read_bytes((self.hdr_ext_len - 1)) if self.hdr_ext_len > 0 else b''
            self.next_header = ProtocolBody(self.next_header_type, self._io)

    @property
    def protocol(self):
        if hasattr(self, '_m_protocol'):
            return self._m_protocol if hasattr(self, '_m_protocol') else None

        self._m_protocol = self._root.ProtocolEnum(self.protocol_num)
        return self._m_protocol if hasattr(self, '_m_protocol') else None

class Ipv4Packet(KaitaiStruct):

    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.b1 = self._io.read_u1()
        self.b2 = self._io.read_u1()
        self.total_length = self._io.read_u2be()
        self.identification = self._io.read_u2be()
        self.b67 = self._io.read_u2be()
        self.ttl = self._io.read_u1()
        self.protocol = self._io.read_u1()
        self.header_checksum = self._io.read_u2be()
        self.src_ip_addr = self._io.read_bytes(4)
        self.dst_ip_addr = self._io.read_bytes(4)
        self._raw_options = self._io.read_bytes((self.ihl_bytes - 20))
        io = KaitaiStream(BytesIO(self._raw_options))
        self.options = self._root.Ipv4Options(io, self, self._root)
        self.read_len = self.total_length if self.total_length > 0 else 64
        self._raw_body = self._io.read_bytes(self.read_len - self.ihl_bytes)
        # self._raw_body = self._io.read_bytes((self.total_length - self.ihl_bytes))
        io = KaitaiStream(BytesIO(self._raw_body))
        self.body = ProtocolBody(self.protocol, io)


    class Ipv4Options(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.entries = []
            i = 0
            while not self._io.is_eof():
                self.entries.append(self._root.Ipv4Option(self._io, self, self._root))
                i += 1


    class Ipv4Option(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.b1 = self._io.read_u1()
            self.len = self._io.read_u1()
            self.body = self._io.read_bytes(((self.len - 2) if self.len > 2 else 0))

        @property
        def copy(self):
            if hasattr(self, '_m_copy'):
                return self._m_copy if hasattr(self, '_m_copy') else None

            self._m_copy = ((self.b1 & 128) >> 7)
            return self._m_copy if hasattr(self, '_m_copy') else None

        @property
        def opt_class(self):
            if hasattr(self, '_m_opt_class'):
                return self._m_opt_class if hasattr(self, '_m_opt_class') else None

            self._m_opt_class = ((self.b1 & 96) >> 5)
            return self._m_opt_class if hasattr(self, '_m_opt_class') else None

        @property
        def number(self):
            if hasattr(self, '_m_number'):
                return self._m_number if hasattr(self, '_m_number') else None

            self._m_number = (self.b1 & 31)
            return self._m_number if hasattr(self, '_m_number') else None


    @property
    def version(self):
        if hasattr(self, '_m_version'):
            return self._m_version if hasattr(self, '_m_version') else None

        self._m_version = ((self.b1 & 240) >> 4)
        return self._m_version if hasattr(self, '_m_version') else None

    @property
    def ihl(self):
        if hasattr(self, '_m_ihl'):
            return self._m_ihl if hasattr(self, '_m_ihl') else None

        self._m_ihl = (self.b1 & 15)
        return self._m_ihl if hasattr(self, '_m_ihl') else None

    @property
    def ihl_bytes(self):
        if hasattr(self, '_m_ihl_bytes'):
            return self._m_ihl_bytes if hasattr(self, '_m_ihl_bytes') else None

        self._m_ihl_bytes = (self.ihl * 4)
        return self._m_ihl_bytes if hasattr(self, '_m_ihl_bytes') else None

class Ipv6Packet(KaitaiStruct):
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.version = self._io.read_bits_int(4)
        self.traffic_class = self._io.read_bits_int(8)
        self.flow_label = self._io.read_bits_int(20)
        self._io.align_to_byte()
        self.payload_length = self._io.read_u2be()
        self.next_header_type = self._io.read_u1()
        self.hop_limit = self._io.read_u1()
        self.src_ipv6_addr = self._io.read_bytes(16)
        self.dst_ipv6_addr = self._io.read_bytes(16)
        self.next_header = ProtocolBody(self.next_header_type, self._io)
        self.rest = self._io.read_bytes_full()

class EthernetFrame(KaitaiStruct):

    class EtherTypeEnum(Enum):
        ipv4 = 2048
        x_75_internet = 2049
        nbs_internet = 2050
        ecma_internet = 2051
        chaosnet = 2052
        x_25_level_3 = 2053
        arp = 2054
        ipv6 = 34525
        lldp = 35020
        unknown = None

    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.dst_mac = self._io.read_bytes(6)
        self.src_mac = self._io.read_bytes(6)
        try:
            self.ether_type = self._root.EtherTypeEnum(self._io.read_u2be())
            _on = self.ether_type
        except:
            self.ether_type = self._root.EtherTypeEnum(None)
            _on = None
        if _on == self._root.EtherTypeEnum.ipv4:
            self._raw_body = self._io.read_bytes_full()
            io = KaitaiStream(BytesIO(self._raw_body))
            self.body = Ipv4Packet(io)
        elif _on == self._root.EtherTypeEnum.ipv6:
            self._raw_body = self._io.read_bytes_full()
            io = KaitaiStream(BytesIO(self._raw_body))
            self.body = Ipv6Packet(io)
        else:
            self.body = self._io.read_bytes_full()

class PacketPpi(KaitaiStruct):

    class PfhType(Enum):
        radio_802_11_common = 2
        radio_802_11n_mac_ext = 3
        radio_802_11n_mac_phy_ext = 4
        spectrum_map = 5
        process_info = 6
        capture_info = 7

    class Linktype(Enum):
        null_linktype = 0
        ethernet = 1
        ax25 = 3
        ieee802_5 = 6
        arcnet_bsd = 7
        slip = 8
        ppp = 9
        fddi = 10
        ppp_hdlc = 50
        ppp_ether = 51
        atm_rfc1483 = 100
        raw = 101
        c_hdlc = 104
        ieee802_11 = 105
        frelay = 107
        loop = 108
        linux_sll = 113
        ltalk = 114
        pflog = 117
        ieee802_11_prism = 119
        ip_over_fc = 122
        sunatm = 123
        ieee802_11_radiotap = 127
        arcnet_linux = 129
        apple_ip_over_ieee1394 = 138
        mtp2_with_phdr = 139
        mtp2 = 140
        mtp3 = 141
        sccp = 142
        docsis = 143
        linux_irda = 144
        user0 = 147
        user1 = 148
        user2 = 149
        user3 = 150
        user4 = 151
        user5 = 152
        user6 = 153
        user7 = 154
        user8 = 155
        user9 = 156
        user10 = 157
        user11 = 158
        user12 = 159
        user13 = 160
        user14 = 161
        user15 = 162
        ieee802_11_avs = 163
        bacnet_ms_tp = 165
        ppp_pppd = 166
        gprs_llc = 169
        gpf_t = 170
        gpf_f = 171
        linux_lapd = 177
        bluetooth_hci_h4 = 187
        usb_linux = 189
        ppi = 192
        ieee802_15_4 = 195
        sita = 196
        erf = 197
        bluetooth_hci_h4_with_phdr = 201
        ax25_kiss = 202
        lapd = 203
        ppp_with_dir = 204
        c_hdlc_with_dir = 205
        frelay_with_dir = 206
        ipmb_linux = 209
        ieee802_15_4_nonask_phy = 215
        usb_linux_mmapped = 220
        fc_2 = 224
        fc_2_with_frame_delims = 225
        ipnet = 226
        can_socketcan = 227
        ipv4 = 228
        ipv6 = 229
        ieee802_15_4_nofcs = 230
        dbus = 231
        dvb_ci = 235
        mux27010 = 236
        stanag_5066_d_pdu = 237
        nflog = 239
        netanalyzer = 240
        netanalyzer_transparent = 241
        ipoib = 242
        mpeg_2_ts = 243
        ng40 = 244
        nfc_llcp = 245
        infiniband = 247
        sctp = 248
        usbpcap = 249
        rtac_serial = 250
        bluetooth_le_ll = 251
        netlink = 253
        bluetooth_linux_monitor = 254
        bluetooth_bredr_bb = 255
        bluetooth_le_ll_with_phdr = 256
        profibus_dl = 257
        pktap = 258
        epon = 259
        ipmi_hpm_2 = 260
        zwave_r1_r2 = 261
        zwave_r3 = 262
        wattstopper_dlm = 263
        iso_14443 = 264

    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.header = self._root.PacketPpiHeader(self._io, self, self._root)
        self._raw_fields = self._io.read_bytes((self.header.pph_len - 8))
        io = KaitaiStream(BytesIO(self._raw_fields))
        self.fields = self._root.PacketPpiFields(io, self, self._root)
        _on = self.header.pph_dlt
        if _on == self._root.Linktype.ppi:
            self._raw_body = self._io.read_bytes_full()
            io = KaitaiStream(BytesIO(self._raw_body))
            self.body = PacketPpi(io)
        elif _on == self._root.Linktype.ethernet:
            self._raw_body = self._io.read_bytes_full()
            io = KaitaiStream(BytesIO(self._raw_body))
            self.body = EthernetFrame(io)
        else:
            self.body = self._io.read_bytes_full()


    class PacketPpiFields(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.entries = []
            i = 0
            while not self._io.is_eof():
                self.entries.append(self._root.PacketPpiField(self._io, self, self._root))
                i += 1


    class Radio80211nMacExtBody(KaitaiStruct):

        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.flags = self._root.MacFlags(self._io, self, self._root)
            self.a_mpdu_id = self._io.read_u4le()
            self.num_delimiters = self._io.read_u1()
            self.reserved = self._io.read_bytes(3)


    class MacFlags(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.unused1 = self._io.read_bits_int(1) != 0
            self.aggregate_delimiter = self._io.read_bits_int(1) != 0
            self.more_aggregates = self._io.read_bits_int(1) != 0
            self.aggregate = self._io.read_bits_int(1) != 0
            self.dup_rx = self._io.read_bits_int(1) != 0
            self.rx_short_guard = self._io.read_bits_int(1) != 0
            self.is_ht_40 = self._io.read_bits_int(1) != 0
            self.greenfield = self._io.read_bits_int(1) != 0
            self._io.align_to_byte()
            self.unused2 = self._io.read_bytes(3)


    class PacketPpiHeader(KaitaiStruct):

        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.pph_version = self._io.read_u1()
            self.pph_flags = self._io.read_u1()
            self.pph_len = self._io.read_u2le()
            self.pph_dlt = self._root.Linktype(self._io.read_u4le())


    class Radio80211CommonBody(KaitaiStruct):

        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.tsf_timer = self._io.read_u8le()
            self.flags = self._io.read_u2le()
            self.rate = self._io.read_u2le()
            self.channel_freq = self._io.read_u2le()
            self.channel_flags = self._io.read_u2le()
            self.fhss_hopset = self._io.read_u1()
            self.fhss_pattern = self._io.read_u1()
            self.dbm_antsignal = self._io.read_s1()
            self.dbm_antnoise = self._io.read_s1()

    class PacketPpiField(KaitaiStruct):

        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.pfh_type = self._root.PfhType(self._io.read_u2le())
            self.pfh_datalen = self._io.read_u2le()
            _on = self.pfh_type
            if _on == self._root.PfhType.radio_802_11_common:
                self._raw_body = self._io.read_bytes(self.pfh_datalen)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.Radio80211CommonBody(io, self, self._root)
            elif _on == self._root.PfhType.radio_802_11n_mac_ext:
                self._raw_body = self._io.read_bytes(self.pfh_datalen)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.Radio80211nMacExtBody(io, self, self._root)
            elif _on == self._root.PfhType.radio_802_11n_mac_phy_ext:
                self._raw_body = self._io.read_bytes(self.pfh_datalen)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.Radio80211nMacPhyExtBody(io, self, self._root)
            else:
                self.body = self._io.read_bytes(self.pfh_datalen)


    class Radio80211nMacPhyExtBody(KaitaiStruct):

        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.flags = self._root.MacFlags(self._io, self, self._root)
            self.a_mpdu_id = self._io.read_u4le()
            self.num_delimiters = self._io.read_u1()
            self.mcs = self._io.read_u1()
            self.num_streams = self._io.read_u1()
            self.rssi_combined = self._io.read_u1()
            self.rssi_ant_ctl = [None] * (4)
            for i in range(4):
                self.rssi_ant_ctl[i] = self._io.read_u1()

            self.rssi_ant_ext = [None] * (4)
            for i in range(4):
                self.rssi_ant_ext[i] = self._io.read_u1()

            self.ext_channel_freq = self._io.read_u2le()
            self.ext_channel_flags = self._root.Radio80211nMacPhyExtBody.ChannelFlags(self._io, self, self._root)
            self.rf_signal_noise = [None] * (4)
            for i in range(4):
                self.rf_signal_noise[i] = self._root.Radio80211nMacPhyExtBody.SignalNoise(self._io, self, self._root)

            self.evm = [None] * (4)
            for i in range(4):
                self.evm[i] = self._io.read_u4le()

        class ChannelFlags(KaitaiStruct):

            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._read()

            def _read(self):
                self.spectrum_2ghz = self._io.read_bits_int(1) != 0
                self.ofdm = self._io.read_bits_int(1) != 0
                self.cck = self._io.read_bits_int(1) != 0
                self.turbo = self._io.read_bits_int(1) != 0
                self.unused = self._io.read_bits_int(8)
                self.gfsk = self._io.read_bits_int(1) != 0
                self.dyn_cck_ofdm = self._io.read_bits_int(1) != 0
                self.only_passive_scan = self._io.read_bits_int(1) != 0
                self.spectrum_5ghz = self._io.read_bits_int(1) != 0


        class SignalNoise(KaitaiStruct):

            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._read()

            def _read(self):
                self.signal = self._io.read_s1()
                self.noise = self._io.read_s1()

class Pcap(KaitaiStruct):

    class Linktype(Enum):
        null_linktype = 0
        ethernet = 1
        ax25 = 3
        ieee802_5 = 6
        arcnet_bsd = 7
        slip = 8
        ppp = 9
        fddi = 10
        ppp_hdlc = 50
        ppp_ether = 51
        atm_rfc1483 = 100
        raw = 101
        c_hdlc = 104
        ieee802_11 = 105
        frelay = 107
        loop = 108
        linux_sll = 113
        ltalk = 114
        pflog = 117
        ieee802_11_prism = 119
        ip_over_fc = 122
        sunatm = 123
        ieee802_11_radiotap = 127
        arcnet_linux = 129
        apple_ip_over_ieee1394 = 138
        mtp2_with_phdr = 139
        mtp2 = 140
        mtp3 = 141
        sccp = 142
        docsis = 143
        linux_irda = 144
        user0 = 147
        user1 = 148
        user2 = 149
        user3 = 150
        user4 = 151
        user5 = 152
        user6 = 153
        user7 = 154
        user8 = 155
        user9 = 156
        user10 = 157
        user11 = 158
        user12 = 159
        user13 = 160
        user14 = 161
        user15 = 162
        ieee802_11_avs = 163
        bacnet_ms_tp = 165
        ppp_pppd = 166
        gprs_llc = 169
        gpf_t = 170
        gpf_f = 171
        linux_lapd = 177
        bluetooth_hci_h4 = 187
        usb_linux = 189
        ppi = 192
        ieee802_15_4 = 195
        sita = 196
        erf = 197
        bluetooth_hci_h4_with_phdr = 201
        ax25_kiss = 202
        lapd = 203
        ppp_with_dir = 204
        c_hdlc_with_dir = 205
        frelay_with_dir = 206
        ipmb_linux = 209
        ieee802_15_4_nonask_phy = 215
        usb_linux_mmapped = 220
        fc_2 = 224
        fc_2_with_frame_delims = 225
        ipnet = 226
        can_socketcan = 227
        ipv4 = 228
        ipv6 = 229
        ieee802_15_4_nofcs = 230
        dbus = 231
        dvb_ci = 235
        mux27010 = 236
        stanag_5066_d_pdu = 237
        nflog = 239
        netanalyzer = 240
        netanalyzer_transparent = 241
        ipoib = 242
        mpeg_2_ts = 243
        ng40 = 244
        nfc_llcp = 245
        infiniband = 247
        sctp = 248
        usbpcap = 249
        rtac_serial = 250
        bluetooth_le_ll = 251
        netlink = 253
        bluetooth_linux_monitor = 254
        bluetooth_bredr_bb = 255
        bluetooth_le_ll_with_phdr = 256
        profibus_dl = 257
        pktap = 258
        epon = 259
        ipmi_hpm_2 = 260
        zwave_r1_r2 = 261
        zwave_r3 = 262
        wattstopper_dlm = 263
        iso_14443 = 264

    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.hdr = self._root.Header(self._io, self, self._root)
        self.packets = []
        i = 0
        while not self._io.is_eof():
            self.packets.append(self._root.Packet(self._io, self, self._root))
            i += 1

    class Header(KaitaiStruct):

        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.magic_number = self._io.ensure_fixed_contents(b"\xD4\xC3\xB2\xA1")
            self.version_major = self._io.read_u2le()
            self.version_minor = self._io.read_u2le()
            self.thiszone = self._io.read_s4le()
            self.sigfigs = self._io.read_u4le()
            self.snaplen = self._io.read_u4le()
            self.network = self._root.Linktype(self._io.read_u4le())

    class Packet(KaitaiStruct):

        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.ts_sec = self._io.read_u4le()
            self.ts_usec = self._io.read_u4le()
            self.incl_len = self._io.read_u4le()
            self.orig_len = self._io.read_u4le()
            _on = self._root.hdr.network
            if _on == self._root.Linktype.ppi:
                self._raw_body = self._io.read_bytes(self.incl_len)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = PacketPpi(io)
            elif _on == self._root.Linktype.ethernet:
                self._raw_body = self._io.read_bytes(self.incl_len)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = EthernetFrame(io)
            else:
                self.body = self._io.read_bytes(self.incl_len)
