import numpy as np, struct, sys, time
t=time.time()
raw=bytearray(open('libil2cpp.so','rb').read())
RELA_OFF,RELA_SZ=0x34ba8,0x3c75018
rela=np.frombuffer(bytes(raw[RELA_OFF:RELA_OFF+RELA_SZ]),dtype=np.uint64).reshape(-1,3)
rel=rela[(rela[:,1]&0xffffffff)==1027]
print('relocs',len(rela),'relative',len(rel),time.time()-t)
arr=np.frombuffer(raw,dtype=np.uint64)
# only apply where r_offset is 8-aligned and inside file-backed region (offset==va for these segs)
offs=rel[:,0]; add=rel[:,2]
ok=(offs%8==0)&(offs<len(raw)-8)
arr[(offs[ok]//8).astype(np.int64)]=add[ok]
open('libil2cpp.reloc.so','wb').write(raw)
print('done',time.time()-t, 'nonrel types', np.unique(rela[:,1]&0xffffffff,return_counts=True))
