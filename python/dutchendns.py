import asyncio
 
class Qu:
    def __init__(self, **kwargs):
        self.nam = kwargs.get('nam')
        self.typ = kwargs.get('typ') or 1
        self.cls = kwargs.get('cls') or 1
    
    def __repr__(self):
        return self.nam.decode()
 
class Rr:
    def __init__(self, **kwargs):
        self.nam = kwargs.get('nam')
        self.typ = kwargs.get('typ') or 1
        self.cls = kwargs.get('cls') or 1
        self.ttl = kwargs.get('ttl') or 0
        self.dat = kwargs.get('dat') or b''
 
    def __repr__(self):
        return '.'.join(str(i) for i in self.dat)
 
class Dns:
    def __init__(self, **kwargs):
        self.i = kwargs.get('i') or 0
        self.f = kwargs.get('f') or 256
        self.qu = kwargs.get('qu') or []
        self.an = kwargs.get('an') or []
        self.au = kwargs.get('au') or []
        self.ad = kwargs.get('ad') or []
 
    def __repr__(self):
        return repr(self.qu + self.an + self.au + self.ad)
 
class Ser:
    def __init__(self):
        self.his = {}
        self.buf = b''
 
    def _put(self, buf):
        self.buf += buf
 
    def _int(self, i, n):
        self._put(i.to_bytes(n, 'big'))
 
    def _nam(self, nam):
        if nam == b'':
            self.buf += b'\x00'
        elif nam in self.his:
            self._int(self.his[nam], 2)
        else:
            bot = nam.split(b'.')[0]
            top = nam[len(bot):][1:]
            self.his[nam] = len(self.buf) | 0xc000
            self._int(len(bot), 1)
            self._put(bot)
            self._nam(top)
 
    def _qu(self, rr):
        self._nam(rr.nam)
        self._int(rr.typ, 2)
        self._int(rr.cls, 2)
 
    def _rr(self, rr):
        self._nam(rr.nam)
        self._int(rr.typ, 2)
        self._int(rr.cls, 2)
        self._int(rr.ttl, 4)
        self._int(len(rr.dat), 2)
        self._put(rr.dat)
 
    def _dns(self, dns):
        self._int(dns.i, 2)
        self._int(dns.f, 2)
        self._int(len(dns.qu), 2)
        self._int(len(dns.an), 2)
        self._int(len(dns.au), 2)
        self._int(len(dns.ad), 2)
 
        for rr in dns.qu:
            self._qu(rr)
        for rr in dns.an:
            self._rr(rr)
        for rr in dns.au:
            self._rr(rr)
        for rr in dns.ad:
            self._rr(rr)
 
class Des:
    def __init__(self, buf):
        self.his = {}
        self.buf = buf
        self.idx = 0
 
    def _get(self, n):
        buf = self.buf[self.idx:][:n]
        self.idx += n
        return buf
 
    def _int(self, n):
        return int.from_bytes(self._get(n), 'big')
 
    def _nam(self):
        if self.buf[self.idx] == 0:
            return self._get(self._int(1))
        elif self.buf[self.idx] & 0xc0 == 0xc0:
            idx = self._int(2)
            if idx not in self.his:
                des = Des(self.buf)
                des.idx = idx & 0x3fff
                self.his[idx] = des._nam()
            return self.his[idx]
        else:
            tmp = self.idx
            idx = self._int(1)
            top = self._get(idx)
            bot = self._nam()
            nam = (top + b'.' + bot).strip(b'.')
            self.his[tmp | 0xc000] = nam
            return nam
 
    def _qu(self):
        rr = Qu()
 
        rr.nam = self._nam()
        rr.typ = self._int(2)
        rr.cls = self._int(2)
 
        return rr
 
    def _rr(self):
        rr = Rr()
 
        rr.nam = self._nam()
        rr.typ = self._int(2)
        rr.cls = self._int(2)
        rr.ttl = self._int(4)
        dat = self._int(2)
        rr.dat = self._get(dat)
 
        return rr
 
    def _dns(self):
        dns = Dns()
 
        dns.i = self._int(2)
        dns.f = self._int(2)
        qu = self._int(2)
        an = self._int(2)
        au = self._int(2)
        ad = self._int(2)
 
        for _ in range(qu):
            dns.qu.append(self._qu())
        for _ in range(an):
            dns.an.append(self._rr())
        for _ in range(au):
            dns.au.append(self._rr())
        for _ in range(ad):
            dns.ad.append(self._rr())
 
        return dns
 
async def _req_dns(srv, dns):
    r, w = await asyncio.open_connection(srv, 53)
 
    for d in dns:
        ser = Ser()
        ser._dns(d)
        w.write(len(ser.buf).to_bytes(2, 'big'))
        w.write(ser.buf)
 
    await w.drain()
 
    results = []
 
    for _ in range(len(dns)):
        if r.at_eof():
            break
 
        idx = int.from_bytes(await r.read(2), 'big')
        des = Des(await r.read(idx))
 
        if idx == 0 or idx != len(des.buf):
            break
 
        results.append(des._dns())
 
    return results
 
async def _req_qus(srv, qus):
    dns = [Dns(i=i, qu=[qu]) for i, qu in enumerate(qus)]
    res = await _req_dns(srv, dns)
    idx = [dns.i for dns in res]
    qus = [i for i, qu in enumerate(qus) if i not in idx]
    
    return (res, qus)
 
class Client:
    def __init__(self, servers=['1.1.1.1'] * 4, bs=256):
        self.queue = asyncio.Queue()
        self.bs = bs
        self.running = True
        self.tasks = []
 
        for srv in servers:
            self.tasks.append(asyncio.create_task(self._run(srv)))
 
    async def __aenter__(self):
        return self
 
    async def __aexit__(self, *args):
        await self.close()
 
    async def _run(self, srv):
        while True:
            queries = []
            queries.append(await self.queue.get())
            while self.queue.qsize() > 0 and len(queries) < self.bs:
                queries.append(self.queue.get_nowait())
            
            qus = [q[0] for q in queries]
            try:
                res, qus = await _req_qus(srv, qus)
            except ConnectionError as e:
                for q in queries:
                    await self.queue.put(q)
                continue
 
            for r in res:
                queries[r.i][1].set_result(r)
            for q in qus:
                await self.queue.put(queries[q])
 
    async def close(self):
        for task in self.tasks:
            task.cancel()
        for task in self.tasks:
            try:
                await task
            except asyncio.CancelledError as e:
                pass
 
    async def query(self, name):
        fut = asyncio.Future()
        qu = Qu(nam=name.encode())
        await self.queue.put((qu, fut))
        res = await fut
 
        for an in res.an:
            if an.typ == 1:
                return '.'.join(str(i) for i in an.dat)
