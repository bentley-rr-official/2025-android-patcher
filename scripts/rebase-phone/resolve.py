import numpy as np, struct, pickle, time
t0=time.time()
raw=open('libil2cpp.reloc.so','rb').read()
d=open('global-metadata.dat','rb').read()
strs=d[0x100:0x100+0x5d0f40]
def S(i):
    e=strs.find(b'\0',i); return strs[i:e].decode('utf8','replace')
def cstr(off):
    e=raw.find(b'\0',off); return raw[off:e].decode('utf8','replace')
types=d[0x220132c:0x220132c+0x4efab0]; NT=len(types)//88
meths=d[0xa80a74:0xa80a74+0xd1b7ac]; NM=len(meths)//36
imgs=d[0x5d1040:0x5d1040+0x3fc0]; NI=len(imgs)//40
# modules
ARR=0x185b83a0
mods={}
i=0
while True:
    p=struct.unpack_from('<Q',raw,ARR+8*i)[0]
    if p==0 or p>len(raw): break
    nm=struct.unpack_from('<Q',raw,p)[0]
    if nm>len(raw): break
    name=cstr(nm)
    if not name.endswith('.dll'): break
    cnt,mp=struct.unpack_from('<IxxxxQ',raw,p+8)
    mods[name]=(cnt,mp,p)
    i+=1
print('modules',len(mods),'images',NI,time.time()-t0)
out=[]
miss=0
for im in range(NI):
    nameIdx,asm,ts,tc,_,_,_,_,_,_=struct.unpack_from('<10i',imgs,im*40)
    iname=S(nameIdx)
    if iname not in mods: miss+=1; continue
    cnt,mp,_=mods[iname]
    for ti in range(ts,ts+tc):
        t=struct.unpack_from('<16i8H2I',types,ti*88)
        tname=S(t[0]); tns=S(t[1]); ms=t[9]; mc=t[16]
        for mi in range(ms,ms+mc):
            m=struct.unpack_from('<7i4H',meths,mi*36)
            rid=m[6]&0xffffff
            if rid==0 or rid>cnt: continue
            va=struct.unpack_from('<Q',raw,mp+8*(rid-1))[0]
            out.append((iname,ti,tns,tname,S(m[0]),mi,m[4],m[3],m[2],va,m[6],m[10]))
print('image-name misses',miss,'methods',len(out),'with ptr',sum(1 for o in out if o[9]),time.time()-t0)
pickle.dump(out,open('methods.pkl','wb'))
