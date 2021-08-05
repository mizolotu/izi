import requests

from lxml import etree
from dicttoxml import dicttoxml

class Odl:

    ns = {
        'n': 'urn:opendaylight:inventory',
        'f': 'urn:opendaylight:flow:inventory',
        'e': 'urn:opendaylight:openflowplugin:extension:nicira:action',
        's': 'urn:opendaylight:flow:statistics'
    }

    xpath = {
        'tables_on_node': '//n:nodes/n:node[./n:id/text()=$node_id]/f:table[./f:flow]/f:id/text()',
        'flows_in_table_on_node': '//n:nodes/n:node[./n:id/text()=$node_id]/f:table[./f:id/text()=$table_id]/f:flow/f:id/text()'
    }

    def __init__(self, ip, port=8181, user='admin', password='admin'):
        self.ip = ip
        self.port = port
        self.auth = requests.auth.HTTPBasicAuth(user, password)
        self.headers = {'Content-Type': 'application/xml', 'Accept': 'application/xml'}
        self.op = 'http://' + ip + ':' + str(port) + '/restconf/operational/opendaylight-inventory:nodes'
        self.cfg = 'http://' + ip + ':' + str(port) + '/restconf/config/opendaylight-inventory:nodes'

    def get_flow_statistics(self, node_id, table_id, count_type):
        url = '{0}/node/{1}/table/{2}'.format(self.op, node_id, table_id)
        req = requests.get(url, auth=self.auth, headers=self.headers, stream=True)
        req.raw.decode_content = True
        tree = etree.parse(req.raw)
        nodes_root = tree.getroot()
        xp_names = '//f:table/f:flow/f:id/text()'
        xp_stats = '//f:table/f:flow/s:flow-statistics/s:{0}-count/text()'.format(count_type)
        names = nodes_root.xpath(xp_names, namespaces=self.ns)
        stats = nodes_root.xpath(xp_stats, namespaces=self.ns)
        return names, stats

    def push_flow(self, node, flow_body):
        xml_root = flow_body.getroot()
        table = xml_root.xpath("//f:flow/f:table_id/text()", namespaces=self.ns)
        flow = xml_root.xpath("//f:flow/f:id/text()", namespaces=self.ns)
        if len(table) > 0 and len(flow) > 0:
            url = self.cfg + '/node/' + node + '/table/' + table[0] + '/flow/' + flow[0]
            body = etree.tostring(flow_body)
            r = requests.put(url=url, data=body, headers=self.headers, auth=self.auth)
            if int(r.status_code) >= 200 and int(r.status_code) < 300:
                code = 0
            else:
                code = 1
                print(body)
                print((r.text))
        else:
            code = -1
        return code

    def delete_config_flow(self, node_id, table_id, flow_id):
        url = '{0}/node/{1}/table/{2}/flow/{3}'.format(self.cfg, node_id, table_id, flow_id)
        r = requests.delete(url=url, headers=self.headers, auth=self.auth)
        if int(r.status_code) >= 200 and int(r.status_code) < 300:
            code = 0
        else:
            code = 1
        return code

    def delete_operational_flow(self, node_id, table_id, flow_id):
        url = '{0}/node/{1}/table/{2}/flow/{3}'.format(self.op, node_id, table_id, flow_id)
        r = requests.delete(url=url, headers=self.headers, auth=self.auth)
        if int(r.status_code) >= 200 and int(r.status_code) < 300:
            code = 0
        else:
            code = 1
        return code

    def find_config_tables(self, node_id):
        req = requests.get(self.cfg, auth=self.auth, headers=self.headers, stream=True)
        req.raw.decode_content = True
        tree = etree.parse(req.raw)
        nodes_root = tree.getroot()
        table_ids = nodes_root.xpath(self.xpath['tables_on_node'], node_id=node_id, namespaces=self.ns)
        return table_ids

    def find_operational_tables(self, node_id):
        req = requests.get(self.op, auth=self.auth, headers=self.headers, stream=True)
        req.raw.decode_content = True
        tree = etree.parse(req.raw)
        nodes_root = tree.getroot()
        table_ids = nodes_root.xpath(self.xpath['tables_on_node'], node_id=node_id, namespaces=self.ns)
        return table_ids

    def find_operational_flows(self, node_id, table_id):
        req = requests.get(self.op, auth=self.auth, headers=self.headers, stream=True)
        req.raw.decode_content = True
        tree = etree.parse(req.raw)
        nodes_root = tree.getroot()
        flow_ids = nodes_root.xpath(self.xpath['flows_in_table_on_node'], node_id=node_id, table_id=table_id, namespaces=self.ns)
        return flow_ids

    def find_config_flows(self, node_id, table_id):
        req = requests.get(self.cfg, auth=self.auth, headers=self.headers, stream=True)
        req.raw.decode_content = True
        tree = etree.parse(req.raw)
        nodes_root = tree.getroot()
        flow_ids = nodes_root.xpath(self.xpath['flows_in_table_on_node'], node_id=node_id, table_id=table_id, namespaces=self.ns)
        return flow_ids

    def delete_operational_table(self, node_id, table_id):
        url = self.op + '/node/' + node_id + '/table/' + table_id
        r = requests.delete(url=url, headers=self.headers, auth=self.auth)
        if int(r.status_code) >= 200 and int(r.status_code) < 300:
            code = 0
        else:
            code = 1
        return code

    def delete_config_table(self, node_id, table_id):
        url = self.cfg + '/node/' + node_id + '/table/' + table_id
        r = requests.delete(url=url, headers=self.headers, auth=self.auth)
        if int(r.status_code) >= 200 and int(r.status_code) < 300:
            code = 0
        else:
            code = 1
        return code

    def flow_exists_in_config(self, node_id, table_id, flow_id):
        url = '{0}/node/{1}/table/{2}'.format(self.cfg, node_id, table_id)
        req = requests.get(url, auth=self.auth, headers=self.headers, stream=True)
        req.raw.decode_content = True
        tree = etree.parse(req.raw)
        nodes_root = tree.getroot()
        xp = '//f:table/f:flow[./f:id/text()=$flow_id]/f:id'
        flow_ids = nodes_root.xpath(xp, flow_id=flow_id, namespaces=self.ns)
        if len(flow_ids) > 0:
            result = True
        else:
            result = False
        return result

    def flow_exists_in_operational(self, node_id, table_id, flow_id):
        url = '{0}/node/{1}/table/{2}'.format(self.op, node_id, table_id)
        req = requests.get(url, auth=self.auth, headers=self.headers, stream=True)
        req.raw.decode_content = True
        tree = etree.parse(req.raw)
        nodes_root = tree.getroot()
        xp = '//f:table/f:flow[./f:id/text()=$flow_id]/f:id'
        flow_ids = nodes_root.xpath(xp, flow_id=flow_id, namespaces=self.ns)
        if len(flow_ids) > 0:
            result = True
        else:
            result = False
        return result

    def input_output(self, node_id, table_id, priority, input, output):
        flow_id = f'i_{input}_o_{output}'
        flow = Flow(node_id, table_id, flow_id, priority, self.ns)
        flow.match([Flow.in_port(input), Flow.ethernet_type(2048)])
        flow.instructions([
            ['apply-actions', [
                {'action': [Flow.output_to_port(output)], 'order': 0, 'ns': 'f'}
            ]]
        ], [0])
        result = self.push_flow(node_id, flow.body)
        if result == 0:
            pushed_flow = {'node_id': node_id, 'table_id': table_id, 'flow_id': flow_id}
        else:
            pushed_flow = {}
        return pushed_flow

    def input_output_and_resubmit(self, node_id, table_id, priority, input, output, goto_table):
        flow_id = f'i_{input}_o_{output}_t_{goto_table}'
        flow = Flow(node_id, table_id, flow_id, priority, self.ns)
        flow.match([Flow.in_port(input), Flow.ethernet_type(2048)])
        flow.instructions([
            Flow.go_to_table(goto_table),
            ['apply-actions', [
                {'action': [Flow.output_to_port(output)], 'order': 0, 'ns': 'f'}
            ]]
        ], [0, 1])
        result = self.push_flow(node_id, flow.body)
        if result == 0:
            pushed_flow = {'node_id': node_id, 'table_id': table_id, 'flow_id': flow_id}
        else:
            pushed_flow = {}
        return pushed_flow

    def resubmit(self, node_id, table_id, priority, goto_table):
        flow_id = f't_{goto_table}'
        flow = Flow(node_id, table_id, flow_id, priority, self.ns)
        flow.match([Flow.ethernet_type(2048)])
        flow.instructions([Flow.go_to_table(goto_table)], [0])
        result = self.push_flow(node_id, flow.body)
        if result == 0:
            pushed_flow = {'node_id': node_id, 'table_id': table_id, 'flow_id': flow_id}
        else:
            pushed_flow = {}
        return pushed_flow

    def input_resubmit(self, node_id, table_id, priority, input, goto_table):
        flow_id = f'i_{input}_t_{goto_table}'
        flow = Flow(node_id, table_id, flow_id, priority, self.ns)
        flow.match([Flow.in_port(input), Flow.ethernet_type(2048)])
        flow.instructions([
            Flow.go_to_table(goto_table),
        ], [0])
        result = self.push_flow(node_id, flow.body)
        if result == 0:
            pushed_flow = {'node_id': node_id, 'table_id': table_id, 'flow_id': flow_id}
        else:
            pushed_flow = {}
        return pushed_flow

    def output(self, node_id, table_id, priority, output):
        flow_id = f'o_{output}'
        flow = Flow(node_id, table_id, flow_id, priority, self.ns)
        flow.match([Flow.ethernet_type(2048)])
        flow.instructions([
            ['apply-actions', [
                {'action': [Flow.output_to_port(output)], 'order': 0, 'ns': 'f'}
            ]]
        ], [0])
        result = self.push_flow(node_id, flow.body)
        if result == 0:
            pushed_flow = {'node_id': node_id, 'table_id': table_id, 'flow_id': flow_id}
        else:
            pushed_flow = {}
        return pushed_flow

    def proto_resubmit(self, node_id, table_id, priority, proto_name, proto_number, goto_table):
        flow_id = 'p_{0}'.format(proto_name)
        flow = Flow(node_id, table_id, flow_id, priority, self.ns)
        flow.match([Flow.ethernet_type(2048), Flow.ip_protocol(proto_number)])
        flow.instructions([Flow.go_to_table(goto_table)], [0])
        result = self.push_flow(node_id, flow.body)
        if result == 0:
            pushed_flow = {'node_id': node_id, 'table_id': table_id, 'flow_id': flow_id}
        else:
            pushed_flow = {}
        return pushed_flow

    def app_resubmit(self, node_id, table_id, priority, proto_name, proto_number, port_dir, port, goto_table):
        flow_id = 'ppp_{0}_{1}_{2}'.format(proto_name, port_dir, port)
        flow = Flow(node_id, table_id, flow_id, priority, self.ns)
        flow.match([Flow.ethernet_type(2048), Flow.ip_protocol(proto_number), Flow.port_direction(proto_name, port_dir, port)])
        flow.instructions([Flow.go_to_table(goto_table)], [0])
        result = self.push_flow(node_id, flow.body)
        if result == 0:
            pushed_flow = {'node_id': node_id, 'table_id': table_id, 'flow_id': flow_id}
        else:
            pushed_flow = {}
        return pushed_flow

    def ip_resubmit(self, node_id, table_id, priority, ip_dir, ip, goto_table, mask=32):
        flow_id = 'ii_{0}_{1}'.format(ip_dir, ip)
        ip_with_mask = '{0}/{1}'.format(ip, mask)
        flow = Flow(node_id, table_id, flow_id, priority, self.ns)
        flow.match([Flow.ethernet_type(2048), Flow.ip_direction(ip_dir, ip_with_mask)])
        flow.instructions([Flow.go_to_table(goto_table)], [0])
        result = self.push_flow(node_id, flow.body)
        if result == 0:
            pushed_flow = {'node_id': node_id, 'table_id': table_id, 'flow_id': flow_id}
        else:
            pushed_flow = {}
        return pushed_flow

    def app_output_and_resubmit(self, node_id, table_id, priority, proto_name, proto_number, port_dir, port, output, goto_table):
        flow_id = 'ppp_{0}_{1}_{2}'.format(proto_name, port_dir, port)
        flow = Flow(node_id, table_id, flow_id, priority, self.ns)
        flow.match([Flow.ethernet_type(2048), Flow.ip_protocol(proto_number), Flow.port_direction(proto_name, port_dir, port)])
        flow.instructions([
            Flow.go_to_table(goto_table),
            ['apply-actions', [
                {'action': [Flow.output_to_port(output)], 'order': 0, 'ns': 'f'}
            ]]
        ], [0, 1])
        result = self.push_flow(node_id, flow.body)
        if result == 0:
            pushed_flow = {'node_id': node_id, 'table_id': table_id, 'flow_id': flow_id}
        else:
            pushed_flow = {}
        return pushed_flow

    def proto_output_and_resubmit(self, node_id, table_id, priority, proto_name, proto_number, output, goto_table):
        flow_id = 'p_{0}'.format(proto_name)
        flow = Flow(node_id, table_id, flow_id, priority, self.ns)
        flow.match([Flow.ethernet_type(2048), Flow.ip_protocol(proto_number)])
        flow.instructions([
            Flow.go_to_table(goto_table),
            ['apply-actions', [
                {'action': [Flow.output_to_port(output)], 'order': 0, 'ns': 'f'}
            ]]
        ], [0, 1])
        result = self.push_flow(node_id, flow.body)
        if result == 0:
            pushed_flow = {'node_id': node_id, 'table_id': table_id, 'flow_id': flow_id}
        else:
            pushed_flow = {}
        return pushed_flow

    def ip_app_output_and_resubmit(self, node_id, table_id, priority, ip_dir, ip, proto_name, proto_number, port_dir, port, output, goto_table, mask=32):
        flow_id = 'iippp_{0}_{1}_{2}_{3}_{4}'.format(ip_dir, ip, proto_name, port_dir, port)
        flow = Flow(node_id, table_id, flow_id, priority, self.ns)
        ip_with_mask = '{0}/{1}'.format(ip, mask)
        flow.match([Flow.ethernet_type(2048), Flow.ip_protocol(proto_number), Flow.ip_direction(ip_dir, ip_with_mask), Flow.port_direction(proto_name, port_dir, port)])
        flow.instructions([
            Flow.go_to_table(goto_table),
            ['apply-actions', [
                {'action': [Flow.output_to_port(output)], 'order': 0, 'ns': 'f'}
            ]]
        ], [0, 1])
        result = self.push_flow(node_id, flow.body)
        if result == 0:
            pushed_flow = {'node_id': node_id, 'table_id': table_id, 'flow_id': flow_id}
        else:
            pushed_flow = {}
        return pushed_flow

    def ip_proto_output_and_resubmit(self, node_id, table_id, priority, ip_dir, ip, proto_name, proto_number, output, goto_table, mask=32):
        flow_id = 'iip_{0}_{1}_{2}'.format(ip_dir, ip, proto_name)
        ip_with_mask = '{0}/{1}'.format(ip, mask)
        flow = Flow(node_id, table_id, flow_id, priority, self.ns)
        flow.match([Flow.ethernet_type(2048), Flow.ip_protocol(proto_number), Flow.ip_direction(ip_dir, ip_with_mask)])
        flow.instructions([
            Flow.go_to_table(goto_table),
            ['apply-actions', [
                {'action': [Flow.output_to_port(output)], 'order': 0, 'ns': 'f'}
            ]]
        ], [0, 1])
        result = self.push_flow(node_id, flow.body)
        if result == 0:
            pushed_flow = {'node_id': node_id, 'table_id': table_id, 'flow_id': flow_id}
        else:
            pushed_flow = {}
        return pushed_flow

    def ip_app_drop(self, node_id, table_id, priority, ip_dir, ip, proto_name, proto_number, port_dir, port, mask=32):
        flow_id = 'iippp_{0}_{1}_{2}_{3}_{4}'.format(ip_dir, ip, proto_name, port_dir, port)
        ip_with_mask = '{0}/{1}'.format(ip, mask)
        flow = Flow(node_id, table_id, flow_id, priority, self.ns)
        flow.match([Flow.ethernet_type(2048), Flow.ip_protocol(proto_number), Flow.ip_direction(ip_dir, ip_with_mask), Flow.port_direction(proto_name, port_dir, port)])
        flow.instructions([
            ['apply-actions', [
                {'action': [['drop-action', None]], 'order': 0, 'ns': 'f'}
            ]]
        ], [0])
        result = self.push_flow(node_id, flow.body)
        if result == 0:
            pushed_flow = {'node_id': node_id, 'table_id': table_id, 'flow_id': flow_id}
        else:
            pushed_flow = {}
        return pushed_flow

    def ip_proto_drop(self, node_id, table_id, priority, ip_dir, ip, proto_name, proto_number, mask=32):
        flow_id = 'iip_{0}_{1}_{2}'.format(ip_dir, ip, proto_name)
        ip_with_mask = '{0}/{1}'.format(ip, mask)
        flow = Flow(node_id, table_id, flow_id, priority, self.ns)
        flow.match([Flow.ethernet_type(2048), Flow.ip_protocol(proto_number), Flow.ip_direction(ip_dir, ip_with_mask)])
        flow.instructions([
            ['apply-actions', [
                {'action': [['drop-action', None]], 'order': 0, 'ns': 'f'}
            ]]
        ], [0])
        result = self.push_flow(node_id, flow.body)
        if result == 0:
            pushed_flow = {'node_id': node_id, 'table_id': table_id, 'flow_id': flow_id}
        else:
            pushed_flow = {}
        return pushed_flow

############################# OLD ########################################################

    def arp_auto_reply(self, node_id, table_id, priority, ip, mac):
        ip_with_mask = '{0}/32'.format(ip[0])
        id = 'table{0}_arp_{1}_{2}'.format(table_id, ip[0], ''.join(mac[0].split(':')))
        flow = Flow(node_id, table_id, id, priority, self.ns)
        flow.match([Flow.ethernet_type(2054), Flow.arp_tpa(ip_with_mask)])
        flow.instructions([
            ['apply-actions', [
                {'action': [*Flow.nx_reg_move('of-eth-src', 'of-eth-dst', 47)], 'order': 0, 'ns': 'e'},
                {'action': [Flow.set_ethernet_src(mac[0])], 'order': 1, 'ns': 'f'},
                {'action': [*Flow.nx_reg_load(2, 'of-arp-op', 15)], 'order': 2, 'ns': 'e'},
                {'action': [*Flow.nx_reg_move('nx-arp-sha', 'nx-arp-tha', 47)], 'order': 3, 'ns': 'e'},
                {'action': [*Flow.nx_reg_move('of-arp-spa', 'of-arp-tpa', 31)], 'order': 4, 'ns': 'e'},
                {'action': [*Flow.nx_reg_load(mac[1], 'nx-arp-sha', 47)], 'order': 5, 'ns': 'e'},
                {'action': [*Flow.nx_reg_load(ip[1], 'of-arp-spa', 31)], 'order': 6, 'ns': 'e'},
                {'action': [Flow.output_to_port('IN_PORT')], 'order': 7, 'ns': 'f'}
            ]]
        ], [0])
        result = self.push_flow(node_id, flow.body)
        pushed_flows = []
        if result == 0:
            pushed_flows.append({'node_id': node_id, 'table_id': table_id, 'flow_id': id})
        return pushed_flows

    def arp_output(self, node_id, table_id, priority, ip, output):
        ip_with_mask = '{0}/32'.format(ip)
        id = 'table{0}_arp_{1}_to_{2}'.format(table_id, ip, output)
        flow = Flow(node_id, table_id, id, priority, self.ns)
        flow.match([Flow.ethernet_type(2054), Flow.arp_tpa(ip_with_mask)])
        flow.instructions([
            ['apply-actions', [
                {'action': [Flow.output_to_port(output)], 'order': 0, 'ns': 'f'}
            ]]
        ], [0])
        result = self.push_flow(node_id, flow.body)
        pushed_flows = []
        if result == 0:
            pushed_flows.append({'node_id': node_id, 'table_id': table_id, 'flow_id': id})
        return pushed_flows

    def ip_dst_output(self, node_id, table_id, priority, ip, output, mask=32):
        ip_with_mask = '{0}/{1}'.format(ip, mask)
        id = 'table{0}_dst_{1}_to_{2}'.format(table_id, ip, output)
        flow = Flow(node_id, table_id, id, priority, self.ns)
        flow.match([Flow.ethernet_type(2048), Flow.ip_dst(ip_with_mask)])
        flow.instructions([
            ['apply-actions', [
                {'action': [Flow.output_to_port(output)], 'order': 0, 'ns': 'f'}
            ]]
        ], [0])
        result = self.push_flow(node_id, flow.body)
        pushed_flows = []
        if result == 0:
            pushed_flows.append({'node_id': node_id, 'table_id': table_id, 'flow_id': id})
        return pushed_flows

    def ip_src_output_and_resubmit(self, node_id, table_id, priority, ip, output, goto_table, mask=32):
        ip_with_mask = '{0}/{1}'.format(ip, mask)
        id = 'table{0}_src_{1}_to_{2}'.format(table_id, ip, output)
        flow = Flow(node_id, table_id, id, priority, self.ns)
        flow.match([Flow.ethernet_type(2048), Flow.ip_src(ip_with_mask)])
        flow.instructions([
            Flow.go_to_table(goto_table),
            ['apply-actions', [
                {'action': [Flow.output_to_port(output)], 'order': 0, 'ns': 'f'}
            ]]
        ], [0, 1])
        result = self.push_flow(node_id, flow.body)
        pushed_flows = []
        if result == 0:
            pushed_flows.append({'node_id': node_id, 'table_id': table_id, 'flow_id': id})
        return pushed_flows

    def ip_dst_mod_ecn_and_output(self, node_id, table_id, priority, ip, ecn, new_ecn, output, mask=32):
        ip_with_mask = '{0}/{1}'.format(ip, mask)
        id = 'table{0}_dst_{1}_ecn_{2}_to_{3}'.format(table_id, ip, ecn, output)
        flow = Flow(node_id, table_id, id, priority, self.ns)
        flow.match([Flow.ethernet_type(2048), Flow.ip_dst(ip_with_mask), Flow.ip_ecn(ecn)])
        flow.instructions([
            ['apply-actions', [
                {'action': [Flow.set_ip_ecn(new_ecn)], 'order': 0, 'ns': 'f'},
                {'action': [Flow.output_to_port(output)], 'order': 1, 'ns': 'f'}
            ]]
        ], [0])
        result = self.push_flow(node_id, flow.body)
        pushed_flows = []
        if result == 0:
            pushed_flows.append({'node_id': node_id, 'table_id': table_id, 'flow_id': id})
        return pushed_flows

    def ip_dst_mod_ecn_and_output_and_resubmit(self, node_id, table_id, priority, ip, ecn, new_ecn, output, goto_table, mask=32):
        ip_with_mask = '{0}/{1}'.format(ip, mask)
        id = 'table{0}_dst_{1}_ecn_{2}_to_{3}_{4}'.format(table_id, ip, ecn, output, goto_table)
        flow = Flow(node_id, table_id, id, priority, self.ns)
        flow.match([Flow.ethernet_type(2048), Flow.ip_dst(ip_with_mask), Flow.ip_ecn(ecn)])
        flow.instructions([
            ['apply-actions', [
                {'action': [Flow.set_ip_ecn(new_ecn)], 'order': 0, 'ns': 'f'},
                {'action': [Flow.output_to_port(output)], 'order': 1, 'ns': 'f'},
                {'action': [*Flow.nx_resubmit(goto_table)], 'order': 2, 'ns': 'e'}
            ]]
        ], [0])
        result = self.push_flow(node_id, flow.body)
        pushed_flows = []
        if result == 0:
            pushed_flows.append({'node_id': node_id, 'table_id': table_id, 'flow_id': id})
        return pushed_flows

    def ip_dst_mod_mac_and_output(self, node_id, table_id, priority, ip, mac, new_mac, output, mask=32):
        ip_with_mask = '{0}/{1}'.format(ip, mask)
        id = 'table{0}_dst_{1}_mac_{2}_to_{3}'.format(table_id, ip, ''.join(mac.split(':')), output)
        flow = Flow(node_id, table_id, id, priority, self.ns)
        flow.match([Flow.ethernet_type(2048), Flow.ip_dst(ip_with_mask), Flow.ethernet_dst(mac)])
        flow.instructions([
            ['apply-actions', [
                {'action': [Flow.set_ethernet_dst(new_mac)], 'order': 0, 'ns': 'f'},
                {'action': [Flow.output_to_port(output)], 'order': 1, 'ns': 'f'}
            ]]
        ], [0])
        result = self.push_flow(node_id, flow.body)
        pushed_flows = []
        if result == 0:
            pushed_flows.append({'node_id': node_id, 'table_id': table_id, 'flow_id': id})
        return pushed_flows

    def ip_dst_mod_ecn_and_mac_and_output(self, node_id, table_id, priority, ip, ecn, mac, new_ecn, new_mac, output, mask=32):
        ip_with_mask = '{0}/{1}'.format(ip, mask)
        id = 'table{0}_dst_{1}_ecn_{2}_mac_{3}_to_{4}'.format(table_id, ip, ecn, ''.join(mac.split(':')), output)
        flow = Flow(node_id, table_id, id, priority, self.ns)
        flow.match([Flow.ethernet_type(2048), Flow.ip_dst(ip_with_mask), Flow.ip_ecn(ecn), Flow.ethernet_dst(mac)])
        flow.instructions([
            ['apply-actions', [
                {'action': [Flow.set_ip_ecn(new_ecn)], 'order': 0, 'ns': 'f'},
                {'action': [Flow.set_ethernet_dst(new_mac)], 'order': 1, 'ns': 'f'},
                {'action': [Flow.output_to_port(output)], 'order': 2, 'ns': 'f'}
            ]]
        ], [0])
        result = self.push_flow(node_id, flow.body)
        pushed_flows = []
        if result == 0:
            pushed_flows.append({'node_id': node_id, 'table_id': table_id, 'flow_id': id})
        return pushed_flows

    def arp_spa_tpa_mod_tpa_and_output(self, node_id, table_id, priority, spa, tpa, new_tpa, output):
        spa_with_mask = '{0}/32'.format(spa)
        tpa_with_mask = '{0}/32'.format(tpa)
        id = 'table{0}_arp_{1}_{2}_to_{3}'.format(table_id, spa, tpa, output)
        flow = Flow(node_id, table_id, id, priority, self.ns)
        flow.match([Flow.ethernet_type(2054), Flow.arp_spa(spa_with_mask), Flow.arp_tpa(tpa_with_mask)])
        flow.instructions([
            ['apply-actions', [
                {'action': [*Flow.nx_reg_load(new_tpa[1], 'of-arp-tpa', 31)], 'order': 0, 'ns': 'e'},
                {'action': [Flow.output_to_port(output)], 'order': 1, 'ns': 'f'}
            ]]
        ], [0])
        result = self.push_flow(node_id, flow.body)
        pushed_flows = []
        if result == 0:
            pushed_flows.append({'node_id': node_id, 'table_id': table_id, 'flow_id': id})
        return pushed_flows

    def arp_spa_tpa_mod_spa_and_output(self, node_id, table_id, priority, spa, tpa, new_spa, output):
        spa_with_mask = '{0}/32'.format(spa)
        tpa_with_mask = '{0}/32'.format(tpa)
        id = 'table{0}_arp_{1}_{2}_to_{3}'.format(table_id, spa, tpa, output)
        flow = Flow(node_id, table_id, id, priority, self.ns)
        flow.match([Flow.ethernet_type(2054), Flow.arp_spa(spa_with_mask), Flow.arp_tpa(tpa_with_mask)])
        flow.instructions([
            ['apply-actions', [
                {'action': [*Flow.nx_reg_load(new_spa[1], 'of-arp-spa', 31)], 'order': 0, 'ns': 'e'},
                {'action': [Flow.output_to_port(output)], 'order': 1, 'ns': 'f'}
            ]]
        ], [0])
        result = self.push_flow(node_id, flow.body)
        pushed_flows = []
        if result == 0:
            pushed_flows.append({'node_id': node_id, 'table_id': table_id, 'flow_id': id})
        return pushed_flows

    def ip_src_dst_port_mod_src_dst_output(self, node_id, table_id, priority, src, dst, proto, port, new_src, new_dst, output):
        src_with_mask = '{0}/32'.format(src)
        dst_with_mask = '{0}/32'.format(dst)
        new_src_with_mask = '{0}/32'.format(new_src)
        new_dst_with_mask = '{0}/32'.format(new_dst)
        id = 'table{0}_ip_{1}_{2}_{3}_{4}_to_{5}'.format(table_id, src, dst, proto[0], port[0], output)
        flow = Flow(node_id, table_id, id, priority, self.ns)
        if port[0] > 0:
            flow.match([Flow.ethernet_type(2048), Flow.ip_src(src_with_mask), Flow.ip_dst(dst_with_mask), Flow.ip_protocol(proto[1]), Flow.port(proto[0], port)])
        else:
            flow.match([Flow.ethernet_type(2048), Flow.ip_src(src_with_mask), Flow.ip_dst(dst_with_mask), Flow.ip_protocol(proto[1])])
        flow.instructions([
            ['apply-actions', [
                {'action': [Flow.set_ip_src(new_src_with_mask)], 'order': 0, 'ns': 'f'},
                {'action': [Flow.set_ip_dst(new_dst_with_mask)], 'order': 1, 'ns': 'f'},
                {'action': [Flow.output_to_port(output)], 'order': 2, 'ns': 'f'}
            ]]
        ], [0])
        result = self.push_flow(node_id, flow.body)
        pushed_flows = []
        if result == 0:
            pushed_flows.append({'node_id': node_id, 'table_id': table_id, 'flow_id': id})
        return pushed_flows

    def ip_src_dst_port_dscp_mod_src_dst_output(self, node_id, table_id, priority, src, dst, proto, port, dscp, new_src, new_dst, output):
        src_with_mask = '{0}/32'.format(src)
        dst_with_mask = '{0}/32'.format(dst)
        new_src_with_mask = '{0}/32'.format(new_src)
        new_dst_with_mask = '{0}/32'.format(new_dst)
        id = 'table{0}_ip_{1}_{2}_{3}_{4}_{5}_to_{6}'.format(table_id, src, dst, proto[0], port[0], dscp, output)
        flow = Flow(node_id, table_id, id, priority, self.ns)
        if port[0] > 0:
            flow.match([Flow.ethernet_type(2048), Flow.ip_src(src_with_mask), Flow.ip_dst(dst_with_mask), Flow.ip_protocol(proto[1]), Flow.port(proto[0], port), Flow.ip_dscp(dscp)])
            priority += 1
        else:
            flow.match([Flow.ethernet_type(2048), Flow.ip_src(src_with_mask), Flow.ip_dst(dst_with_mask), Flow.ip_protocol(proto[1]), Flow.ip_dscp(dscp)])
        flow.instructions([
            ['apply-actions', [
                {'action': [Flow.set_ip_src(new_src_with_mask)], 'order': 0, 'ns': 'f'},
                {'action': [Flow.set_ip_dst(new_dst_with_mask)], 'order': 1, 'ns': 'f'},
                {'action': [Flow.output_to_port(output)], 'order': 2, 'ns': 'f'}
            ]]
        ], [0])
        result = self.push_flow(node_id, flow.body)
        pushed_flows = []
        if result == 0:
            pushed_flows.append({'node_id': node_id, 'table_id': table_id, 'flow_id': id})
        return pushed_flows

    def ip_src_dst_port_dscp_drop(self, node_id, table_id, priority, src, dst, proto, port, dscp):
        src_with_mask = '{0}/32'.format(src)
        dst_with_mask = '{0}/32'.format(dst)
        id = 'table{0}_ip_{1}_{2}_{3}_{4}_{5}_drop'.format(table_id, src, dst, proto[0], port[0], dscp)
        flow = Flow(node_id, table_id, id, priority, self.ns)
        if port[0] > 0:
            flow.match([Flow.ethernet_type(2048), Flow.ip_src(src_with_mask), Flow.ip_dst(dst_with_mask), Flow.ip_protocol(proto[1]), Flow.port(proto[0], port), Flow.ip_dscp(dscp)])
            priority += 1
        else:
            flow.match([Flow.ethernet_type(2048), Flow.ip_src(src_with_mask), Flow.ip_dst(dst_with_mask), Flow.ip_protocol(proto[1]), Flow.ip_dscp(dscp)])
        flow.instructions([
            ['apply-actions', [
                {'action': [['drop-action', None]], 'order': 0, 'ns': 'f'}
            ]]
        ], [0])
        result = self.push_flow(node_id, flow.body)
        pushed_flows = []
        if result == 0:
            pushed_flows.append({'node_id': node_id, 'table_id': table_id, 'flow_id': id})
        return pushed_flows

    def ip_src_dst_port_mod_src_dst_mac_and_resubmit(self, node_id, table_id, priority, src, dst, proto, port, new_src, new_dst, new_mac, goto_table):
        src_with_mask = '{0}/32'.format(src)
        dst_with_mask = '{0}/32'.format(dst)
        new_src_with_mask = '{0}/32'.format(new_src)
        new_dst_with_mask = '{0}/32'.format(new_dst)
        id = 'table{0}_ip_{1}_{2}_{3}_{4}_goto_{5}'.format(table_id, src, dst, proto[0], port[0], goto_table)
        flow = Flow(node_id, table_id, id, priority, self.ns)
        if port[0] > 0:
            flow.match([Flow.ethernet_type(2048), Flow.ip_src(src_with_mask), Flow.ip_dst(dst_with_mask), Flow.ip_protocol(proto[1]), Flow.port(proto[0], port)])
            priority += 1
        else:
            flow.match([Flow.ethernet_type(2048), Flow.ip_src(src_with_mask), Flow.ip_dst(dst_with_mask), Flow.ip_protocol(proto[1])])
        flow.instructions([
            Flow.go_to_table(goto_table),
            ['apply-actions', [
                {'action': [Flow.set_ip_src(new_src_with_mask)], 'order': 0, 'ns': 'f'},
                {'action': [Flow.set_ip_dst(new_dst_with_mask)], 'order': 1, 'ns': 'f'},
                {'action': [Flow.set_ethernet_src(new_mac)], 'order': 2, 'ns': 'f'},
            ]]
        ], [0, 1])
        result = self.push_flow(node_id, flow.body)
        pushed_flows = []
        if result == 0:
            pushed_flows.append({'node_id': node_id, 'table_id': table_id, 'flow_id': id})
        return pushed_flows

    def ip_src_dst_port_mod_src_dst_macs_and_resubmit(self, node_id, table_id, priority, src, dst, proto, port, new_src, new_dst, new_mac_src, new_mac_dst, goto_table):
        src_with_mask = '{0}/32'.format(src)
        dst_with_mask = '{0}/32'.format(dst)
        new_src_with_mask = '{0}/32'.format(new_src)
        new_dst_with_mask = '{0}/32'.format(new_dst)
        id = 'table{0}_ip_{1}_{2}_{3}_{4}_goto_{5}'.format(table_id, src, dst, proto[0], port[0], goto_table)
        flow = Flow(node_id, table_id, id, priority, self.ns)
        if port[0] > 0:
            flow.match([Flow.ethernet_type(2048), Flow.ip_src(src_with_mask), Flow.ip_dst(dst_with_mask), Flow.ip_protocol(proto[1]), Flow.port(proto[0], port)])
            priority += 1
        else:
            flow.match([Flow.ethernet_type(2048), Flow.ip_src(src_with_mask), Flow.ip_dst(dst_with_mask), Flow.ip_protocol(proto[1])])
        flow.instructions([
            Flow.go_to_table(goto_table),
            ['apply-actions', [
                {'action': [Flow.set_ip_src(new_src_with_mask)], 'order': 0, 'ns': 'f'},
                {'action': [Flow.set_ip_dst(new_dst_with_mask)], 'order': 1, 'ns': 'f'},
                {'action': [Flow.set_ethernet_src(new_mac_src)], 'order': 2, 'ns': 'f'},
                {'action': [Flow.set_ethernet_dst(new_mac_dst)], 'order': 3, 'ns': 'f'},
            ]]
        ], [0, 1])
        result = self.push_flow(node_id, flow.body)
        pushed_flows = []
        if result == 0:
            pushed_flows.append({'node_id': node_id, 'table_id': table_id, 'flow_id': id})

        return pushed_flows

    def ip_src_dst_port_mod_mac_and_output(self, node_id, table_id, priority, src, dst, proto, port, new_mac, output):
        src_with_mask = '{0}/32'.format(src)
        dst_with_mask = '{0}/32'.format(dst)
        id = 'table{0}_ip_{1}_{2}_{3}_{4}_to_{5}'.format(table_id, src, dst, proto[0], port[0], output)
        flow = Flow(node_id, table_id, id, priority, self.ns)
        if port[0] > 0:
            flow.match([Flow.ethernet_type(2048), Flow.ip_src(src_with_mask), Flow.ip_dst(dst_with_mask), Flow.ip_protocol(proto[1]), Flow.port(proto[0], port)])
            priority += 1
        else:
            flow.match([Flow.ethernet_type(2048), Flow.ip_src(src_with_mask), Flow.ip_dst(dst_with_mask), Flow.ip_protocol(proto[1])])
        flow.instructions([
            ['apply-actions', [
                {'action': [Flow.set_ethernet_dst(new_mac)], 'order': 0, 'ns': 'f'},
                {'action': [Flow.output_to_port(output)], 'order': 1, 'ns': 'f'}
            ]]
        ], [0])
        result = self.push_flow(node_id, flow.body)
        pushed_flows = []
        if result == 0:
            pushed_flows.append({'node_id': node_id, 'table_id': table_id, 'flow_id': id})

    def ip_src_dst_port_mac_output(self, node_id, table_id, priority, src, dst, proto, port, mac, output):
        src_with_mask = '{0}/32'.format(src)
        dst_with_mask = '{0}/32'.format(dst)
        id = 'table{0}_ip_{1}_{2}_{3}_{4}_{5}_to_{6}'.format(table_id, src, dst, proto[0], port[0], mac, output)
        flow = Flow(node_id, table_id, id, priority, self.ns)
        if port[0] > 0:
            flow.match([Flow.ethernet_type(2048), Flow.ip_src(src_with_mask), Flow.ip_dst(dst_with_mask), Flow.ip_protocol(proto[1]), Flow.port(proto[0], port), Flow.ethernet_src(mac)])
            priority += 1
        else:
            flow.match([Flow.ethernet_type(2048), Flow.ip_src(src_with_mask), Flow.ip_dst(dst_with_mask), Flow.ip_protocol(proto[1]), Flow.ethernet_src(mac)])
        flow.instructions([
            ['apply-actions', [
                {'action': [Flow.output_to_port(output)], 'order': 0, 'ns': 'f'}
            ]]
        ], [0])
        result = self.push_flow(node_id, flow.body)
        pushed_flows = []
        if result == 0:
            pushed_flows.append({'node_id': node_id, 'table_id': table_id, 'flow_id': id})

    # not used:

    def ip_src_dst_port_ecn_mod_src_dst_ecn_mac_output_and_resubmit(self, node_id, table_id, priority, src, dst, proto, port, ecn, new_src, new_dst, new_ecn, new_mac, output, goto_table):
        src_with_mask = '{0}/32'.format(src)
        dst_with_mask = '{0}/32'.format(dst)
        new_src_with_mask = '{0}/32'.format(new_src)
        new_dst_with_mask = '{0}/32'.format(new_dst)
        id = 'table{0}_ip_{1}_{2}_{3}_{4}_{5}_to_{6}'.format(table_id, src, dst, proto[0], port[0], ecn, output)
        flow = Flow(node_id, table_id, id, priority, self.ns)
        if port[0] > 0:
            flow.match([Flow.ethernet_type(2048), Flow.ip_src(src_with_mask), Flow.ip_dst(dst_with_mask), Flow.ip_protocol(proto[1]), Flow.port(proto[0], port), Flow.ip_dscp(dscp), Flow.ip_ecn(ecn)])
        else:
            flow.match([Flow.ethernet_type(2048), Flow.ip_src(src_with_mask), Flow.ip_dst(dst_with_mask), Flow.ip_protocol(proto[1]), Flow.ip_dscp(dscp), Flow.ip_ecn(ecn)])
        flow.instructions([
            Flow.go_to_table(goto_table),
            ['apply-actions', [
                {'action': [Flow.set_ip_src(new_src_with_mask)], 'order': 0, 'ns': 'f'},
                {'action': [Flow.set_ip_dst(new_dst_with_mask)], 'order': 1, 'ns': 'f'},
                {'action': [Flow.set_ip_ecn(new_ecn)], 'order': 2, 'ns': 'f'},
                {'action': [Flow.set_ethernet_src(new_mac)], 'order': 3, 'ns': 'f'},
                {'action': [Flow.output_to_port(output)], 'order': 4, 'ns': 'f'}
            ]]
        ], [0, 1])
        result = self.push_flow(node_id, flow.body)
        pushed_flows = []
        if result == 0:
            pushed_flows.append({'node_id': node_id, 'table_id': table_id, 'flow_id': id})

    def ip_src_dst_port_dscp_ecn_mod_src_dst_ecn_macs_output_and_resubmit(self, node_id, table_id, priority, src, dst, proto, port, dscp, ecn, new_src, new_dst, new_ecn, new_mac_src, new_mac_dst, output, goto_table):
        src_with_mask = '{0}/32'.format(src)
        dst_with_mask = '{0}/32'.format(dst)
        new_src_with_mask = '{0}/32'.format(new_src)
        new_dst_with_mask = '{0}/32'.format(new_dst)
        id = 'table{0}_ip_{1}_{2}_{3}_{4}_{5}_{6}_to_{7}'.format(table_id, src, dst, proto[0], port[0], dscp, ecn, output)
        flow = Flow(node_id, table_id, id, priority, self.ns)
        flow.match([Flow.ethernet_type(2048), Flow.ip_src(src_with_mask), Flow.ip_dst(dst_with_mask), Flow.ip_protocol(proto[1]), Flow.port(proto[0], port), Flow.ip_dscp(dscp), Flow.ip_ecn(ecn)])
        flow.instructions([
            Flow.go_to_table(goto_table),
            ['apply-actions', [
                {'action': [Flow.set_ip_src(new_src_with_mask)], 'order': 0, 'ns': 'f'},
                {'action': [Flow.set_ip_dst(new_dst_with_mask)], 'order': 1, 'ns': 'f'},
                {'action': [Flow.set_ip_ecn(new_ecn)], 'order': 2, 'ns': 'f'},
                {'action': [Flow.set_ethernet_src(new_mac_src)], 'order': 3, 'ns': 'f'},
                {'action': [Flow.set_ethernet_dst(new_mac_dst)], 'order': 4, 'ns': 'f'},
                {'action': [Flow.output_to_port(output)], 'order': 5, 'ns': 'f'}
            ]]
        ], [0, 1])
        result = self.push_flow(node_id, flow.body)
        pushed_flows = []
        if result == 0:
            pushed_flows.append({'node_id': node_id, 'table_id': table_id, 'flow_id': id})




class Flow():

    def __init__(self, switch, table, id, priority, ns, timeout=0):
        self.switch = switch
        self.table = table
        self.id = id
        self.priority = priority
        self.timeout = timeout
        self.ns = ns
        flow_body_dict = {
            'id': self.id,
            'table_id': self.table,
            'priority': self.priority,
            'hard-timeout': self.timeout,
            'match': {},
            'instructions': {}
        }
        flow_body_bytes = dicttoxml(flow_body_dict, root=False, attr_type=False)
        flow_str = '<flow xmlns="' + self.ns['f'] + '">' + flow_body_bytes.decode("utf-8") + '</flow>'
        self.body = etree.fromstring(flow_str).getroottree()

    def match(self, match_list):
        match_found = self.body.find('f:match', namespaces=self.ns)
        for item in match_list:
            last_element_found = match_found
            xp = 'f:match'
            for i in range(len(item)-1):
                xp += '/{0}:{1}'.format('f', item[i])
                element_found = self.body.xpath(xp, namespaces=self.ns)
                if element_found == []:
                    if i == len(item) - 2:
                        etree.SubElement(last_element_found, '{%s}%s' % (self.ns['f'], item[i])).text = str(item[i+1])
                    else:
                        last_element_found = etree.SubElement(last_element_found, '{%s}%s' % (self.ns['f'], item[i]))
                else:
                    last_element_found = element_found[0]

    def instructions(self, instruction_list, order_list):
        instructions_found = self.body.find('f:instructions', namespaces=self.ns)
        for i_item,o_item in zip(instruction_list,order_list):
            instruction_found = etree.SubElement(instructions_found, '{%s}%s' % (self.ns['f'], 'instruction'))
            etree.SubElement(instruction_found, '{%s}%s' % (self.ns['f'], 'order')).text = str(o_item)
            element_found = instruction_found
            if i_item[0] == 'apply-actions':
                self.apply_actions(element_found, [item['action'] for item in i_item[1]], [item['order'] for item in i_item[1]], [item['ns'] for item in i_item[1]])
            else:
                for i in range(len(i_item) - 1):
                    if i == len(i_item) - 2:
                        etree.SubElement(element_found, '{%s}%s' % (self.ns['f'], i_item[i])).text = str(i_item[i + 1])
                    else:
                        element_found = etree.SubElement(element_found, '{%s}%s' % (self.ns['f'], i_item[i]))

    def apply_actions(self, instruction, action_list, order_list, ns_list):
        apply_actions = etree.SubElement(instruction, '{%s}%s' % (self.ns['f'], 'apply-actions'))
        for a_item,o_item,n_item in zip(action_list,order_list,ns_list):
            new_action = etree.SubElement(apply_actions, '{%s}%s' % (self.ns['f'], 'action'))
            etree.SubElement(new_action, '{%s}%s' % (self.ns['f'], 'order')).text = str(o_item)
            last_element_found = new_action
            for i in range(len(a_item)):
                xp = 'f:instructions/f:instruction/f:apply-actions/f:action[./f:order/text()=$ord]'
                for j in range(len(a_item[i])-1):
                    xp += '/{0}:{1}'.format(n_item,a_item[i][j])
                    element_found = self.body.xpath(xp, ord=o_item, namespaces=self.ns)
                    if element_found == []:
                        if j == len(a_item[i]) - 2 and a_item[i][j+1] != None:
                            etree.SubElement(last_element_found, '{%s}%s' % (self.ns[n_item], a_item[i][j])).text = str(a_item[i][j+1])
                        else:
                            last_element_found = etree.SubElement(last_element_found, '{%s}%s' % (self.ns[n_item], a_item[i][j]))
                    else:
                        last_element_found = element_found[0]

    @staticmethod
    def in_port(port):
        inp = ['in-port', port]
        return inp

    @staticmethod
    def ethernet_type(etype):
        eth_type = ['ethernet-match','ethernet-type','type', etype]
        return eth_type

    @staticmethod
    def ethernet_src(mac):
        eth_src = ['ethernet-match', 'ethernet-source', 'address', mac]
        return eth_src

    @staticmethod
    def ethernet_dst(mac):
        eth_dst = ['ethernet-match', 'ethernet-destination', 'address', mac]
        return eth_dst

    @staticmethod
    def arp_spa(ip):
        arp_sta = ['arp-source-transport-address', ip]
        return arp_sta

    @staticmethod
    def arp_tpa(ip):
        arp_tta = ['arp-target-transport-address', ip]
        return arp_tta

    @staticmethod
    def ip_protocol(proto):
        ip_proto = ['ip-match', 'ip-protocol', proto]
        return ip_proto

    @staticmethod
    def ip_direction(direction, ip):
        result = ['ipv4-{0}'.format(direction), ip]
        return result

    @staticmethod
    def port_direction(proto_name, direction, port):
        result = ['{0}-{1}-port'.format(proto_name, direction), port]
        return result

    @staticmethod
    def ip_src(src):
        ip_s = ['ipv4-source', src]
        return ip_s

    @staticmethod
    def ip_dst(dst):
        ip_d = ['ipv4-destination', dst]
        return ip_d

    @staticmethod
    def port(proto, port):
        p_s = ['{0}-{1}-port'.format(proto, port[1]), port[0]]
        return p_s

    @staticmethod
    def ip_ecn(ecn):
        ip_e = ['ip-match', 'ip-ecn', ecn]
        return ip_e

    @staticmethod
    def ip_dscp(dscp):
        ip_d = ['ip-match', 'ip-dscp', dscp]
        return ip_d

    @staticmethod
    def go_to_table(table):
        to_table = ['go-to-table', 'table_id', table]
        return to_table

    @staticmethod
    def output_to_port(connector):
        to_port = ['output-action', 'output-node-connector', connector]
        return to_port

    @staticmethod
    def nx_reg_move(src, dst, size):
        nx_reg_move_src_dst = [
            ['nx-reg-move', 'src', src, None],
            ['nx-reg-move', 'src', 'start', 0],
            ['nx-reg-move', 'src', 'end', size],
            ['nx-reg-move', 'dst', dst, None],
            ['nx-reg-move', 'dst', 'start', 0],
            ['nx-reg-move', 'dst', 'end', size]
        ]
        return nx_reg_move_src_dst

    @staticmethod
    def nx_reg_load(value, dst, size, start=0):
        nx_reg_load_value = [
            ['nx-reg-load', 'value', value],
            ['nx-reg-load', 'dst', dst, None],
            ['nx-reg-load', 'dst', 'start', start],
            ['nx-reg-load', 'dst', 'end', size]
        ]
        return nx_reg_load_value

    @staticmethod
    def nx_resubmit(table, port=65528):
        nx_resubmit_to_table = [
            ['nx-resubmit', 'in-port', port],
            ['nx-resubmit', 'table', table]
        ]
        return nx_resubmit_to_table

    @staticmethod
    def set_ethernet_src(mac):
        eth_src = ['set-field', 'ethernet-match', 'ethernet-source', 'address', mac]
        return eth_src

    @staticmethod
    def set_ethernet_dst(mac):
        eth_src = ['set-field', 'ethernet-match', 'ethernet-destination', 'address', mac]
        return eth_src

    @staticmethod
    def set_ip_ecn(ecn):
        ip_ecn = ['set-field', 'ip-match', 'ip-ecn', ecn]
        return ip_ecn

    @staticmethod
    def set_ip_src(ip):
        ip_set = ['set-field', 'ipv4-source', ip]
        return ip_set

    @staticmethod
    def set_ip_dst(ip):
        ip_set = ['set-field', 'ipv4-destination', ip]
        return ip_set