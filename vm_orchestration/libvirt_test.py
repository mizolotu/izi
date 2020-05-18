import libvirt

conn = libvirt.open()

pools = conn.listAllStoragePools(0)

for pool in pools:

    #check if pool is active
    if pool.isActive() == 0:
        #activate pool
        pool.create()

    stgvols = pool.listVolumes()
    print('Storage pool: ' + pool.name())
    print(stgvols)
    for stgvol in stgvols :
        print('  Storage vol: ' + stgvol)