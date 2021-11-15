import os.path as osp

from common.data import find_data_files
from config import raw_dir
from common.data import find_flows_by_port, find_flows_by_ip

if __name__ == '__main__':
    output_name = 'log.tmp'
    flow_ids, flow_tss = [], []
    ip = '18.216.254.154'
    port = 51527 # 35076
    proto = 6
    dirname = 'Thursday-01-03-2018'
    dnames, fnames = find_data_files(raw_dir)
    dcount = 0
    for dname, fname_list in zip(dnames, fnames):
        if dname == dirname:
            dcount += 1
            print('Checking files in directory {0}/{1}: {2}'.format(dcount, len(dnames), dname))
            idfs = [osp.join(dname, fname) for fname in fname_list]
            input_fnames = [osp.join(raw_dir, df) for df in idfs]
            fcount = 0
            for input_fname in input_fnames:
                fcount += 1
                print('Checking file {0}/{1}: {2}'.format(fcount, len(input_fnames), input_fname))
                flow_ids, flow_tss = find_flows_by_ip(input_fname, flow_ids, flow_tss, port, proto)
                for flow_id, flow_ts in zip(flow_ids, flow_tss):
                    print(flow_id, flow_ts)

