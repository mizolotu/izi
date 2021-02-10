import json, requests
import argparse as arp

if __name__ == '__main__':

    parser = arp.ArgumentParser(description='Setup IDS.')
    parser.add_argument('-v', '--vms', help='File with vms', default='logs/vms.json')
    parser.add_argument('-i', '--ids', help='IDS index', default='1')
    parser.add_argument('-p', '--port', help='IDS port', default=5000, type=int)
    parser.add_argument('-d', '--dscp', help='DSCP label', default=0, type=int)
    parser.add_argument('-m', '--model', help='Model index', default=0, type=int)
    parser.add_argument('-t', '--threshold', help='Threshold index', default=0, type=int)
    args = parser.parse_args()

    with open(args.vms, 'r') as f:
        vms = json.load(f)

    ids_vm = [vm for vm in vms if vm['vm'].startswith('ids') and vm['vm'].endswith(args.ids)]
    assert len(ids_vm) == 1
    ids_vm = ids_vm[0]

    dscp_url = 'http://{0}:{1}/dscp'.format(ids_vm['mgmt'], args.port)
    requests.post(dscp_url, json={'dscp': args.dscp})

    model_url = 'http://{0}:{1}/model'.format(ids_vm['mgmt'], args.port)
    requests.post(model_url, json={'model': args.model})

    thr_url = 'http://{0}:{1}/threshold'.format(ids_vm['mgmt'], args.port)
    requests.post(thr_url, json={'threshold': args.threshold})