import http.server,json,pathlib,subprocess,threading,time,uuid,os,secrets
BASE=pathlib.Path(__file__).resolve().parent
DATA=BASE/'data';DATA.mkdir(exist_ok=True)
NET='codex-network-lab';CLIENT=NET+'-client';SERVER=NET+'-server';IMAGE=NET+':local';LABEL='codex.network-lab=v1'
TOKEN=secrets.token_urlsafe(32)
LOCK=threading.Lock()
state={'ready':False,'rules':[{'port':8000,'policy':'ALLOW'},{'port':9000,'policy':'ALERT'},{'port':8080,'policy':'BLOCK'}],'events':[],'ebpf':[],'sensor':'not started'}
traceproc=None
def run(*args):
    p=subprocess.run(args,capture_output=True,text=True,timeout=180)
    if p.returncode: raise RuntimeError((p.stderr or p.stdout)[-1800:])
    return p.stdout.strip()
def save():
    temp=DATA/'config.tmp';temp.write_text(json.dumps(state['rules']));temp.replace(DATA/'config.json')
def fw(*args):
    return run('docker','run','--rm','--cap-drop=ALL','--cap-add=NET_ADMIN','--network','container:'+CLIENT,IMAGE,'iptables','-w',*args)
def policy():
    try: fw('-N','NETDEMO')
    except RuntimeError: fw('-S','NETDEMO')
    try: fw('-C','OUTPUT','-j','NETDEMO')
    except RuntimeError: fw('-I','OUTPUT','1','-j','NETDEMO')
    fw('-F','NETDEMO')
    for r in state['rules']:
        if r['policy']=='BLOCK':fw('-A','NETDEMO','-p','tcp','--dport',str(r['port']),'-j','REJECT','--reject-with','tcp-reset')
def counters():
    return fw('-nvxL','NETDEMO')
def sensor():
    global traceproc
    if traceproc and traceproc.poll() is None: traceproc.terminate();traceproc.wait(timeout=10)
    try:
        obj=json.loads(run('docker','inspect',CLIENT))[0];pid=obj['State']['Pid']
        path=next(x.split('::')[1] for x in pathlib.Path(f'/proc/{pid}/cgroup').read_text().splitlines() if x.startswith('0::'))
        cg=os.stat('/sys/fs/cgroup'+path).st_ino
        stub=BASE/'btf-only/include/linux';stub.mkdir(parents=True,exist_ok=True);(stub/'kconfig.h').write_text('/* BTF-only tracer */')
        program='''struct demo_addr { unsigned short family; unsigned short port; unsigned int addr; };
BEGIN { printf("READY\\n"); }
kprobe:tcp_v4_connect /cgroup == CG/ { $a=(struct demo_addr *)arg1; $p=$a->port; @port[tid]=($p >> 8) | (($p & 255) << 8); }
kretprobe:tcp_v4_connect /@port[tid]/ { printf("EV %d %d %d\\n",pid,@port[tid],retval); delete(@port[tid]); }
END { clear(@port); }
'''.replace('CG',str(cg))
        (BASE/'trace.bt').write_text(program)
        env=dict(os.environ,BPFTRACE_KERNEL_SOURCE=str(BASE/'btf-only'),BPFTRACE_KERNEL_BUILD=str(BASE/'btf-only'),BPFTRACE_BTF='/sys/kernel/btf/vmlinux')
        traceproc=subprocess.Popen(['bpftrace','-q','-B','none',str(BASE/'trace.bt')],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
        state['sensor']='starting'
        def read(proc):
            for line in proc.stdout:
                if line.strip()=='READY':state['sensor']='live · cgroup '+str(cg)
                elif line.startswith('EV '):
                    _,pid,port,ret=line.split();e={'time':time.time(),'pid':int(pid),'port':int(port),'return':int(ret),'cgroup':cg}
                    state['ebpf'].insert(0,e);del state['ebpf'][100:]
                elif line.strip(): state['sensor']=line.strip()[:180]
            if proc==traceproc:state['sensor']='stopped: '+state['sensor']
        threading.Thread(target=read,args=(traceproc,),daemon=True).start()
    except Exception as e:state['sensor']='unavailable: '+str(e)[:180]
def setup():
    run('docker','build','-t',IMAGE,str(BASE));save()
    existing=subprocess.run(['docker','network','inspect',NET],capture_output=True,text=True)
    if existing.returncode:run('docker','network','create','--internal','--label',LABEL,NET)
    elif json.loads(existing.stdout)[0].get('Labels',{}).get('codex.network-lab')!='v1':raise RuntimeError('Network name belongs to another project')
    for name in (SERVER,CLIENT):
        p=subprocess.run(['docker','inspect',name],capture_output=True,text=True)
        if p.returncode==0:
            obj=json.loads(p.stdout)[0]
            if obj['Config'].get('Labels',{}).get('codex.network-lab')!='v1':raise RuntimeError('Container name belongs to another project')
            run('docker','start',name);continue
        cmd=['docker','run','-d','--name',name,'--label',LABEL,'--network',NET]
        if name==SERVER:cmd+=['--mount',f'type=bind,src={DATA},dst=/data','--mount',f'type=bind,src={BASE / "service.py"},dst=/service.py,readonly',IMAGE,'python','-u','/service.py']
        else:cmd += [IMAGE,'python','-c','import time;time.sleep(604800)']
        run(*cmd)
    policy();state['ready']=True
def validate(rules):
    if not isinstance(rules,list) or not 1<=len(rules)<=12:raise ValueError('เลือก 1–12 พอร์ต')
    seen=set()
    for r in rules:
        if type(r.get('port')) is not int or not 1024<=r['port']<=65535 or r['port'] in seen or r.get('policy') not in ('ALLOW','ALERT','BLOCK'):raise ValueError('พอร์ตต้องไม่ซ้ำ อยู่ระหว่าง 1024–65535 และเลือกกฎให้ครบ')
        seen.add(r['port'])
def request(port):
    if type(port) is not int or not 1<=port<=65535:raise ValueError('กรอกพอร์ต 1–65535')
    rule=next((r for r in state['rules'] if r['port']==port),None)
    if not rule:rule={'port':port,'policy':'UNCONFIGURED'}
    rid=uuid.uuid4().hex[:10];before=counters();start=time.monotonic()
    code=f'''import urllib.request,json
try:
 r=urllib.request.urlopen("http://{SERVER}:{port}/{rid}",timeout=3); print(json.dumps({{"ok":True,"http":r.status}}))
except Exception as e: print(json.dumps({{"ok":False,"error":str(e)}}))
'''
    result=json.loads(run('docker','exec',CLIENT,'python','-c',code));after=counters()
    received=any(json.loads(x).get('path')=='/'+rid for x in (DATA/'received.jsonl').read_text().splitlines()) if (DATA/'received.jsonl').exists() else False
    blocked=not result['ok'] and rule['policy']=='BLOCK' and before!=after
    status=('ALERT' if rule['policy']=='ALERT' else 'ALLOW') if result['ok'] and received else ('BLOCK' if blocked else 'ERROR')
    e={'id':rid,'time':time.time(),'port':port,'policy':rule['policy'],'status':status,'received':received,'ms':round((time.monotonic()-start)*1000),'result':result}
    state['events'].insert(0,e);del state['events'][100:]
    with (DATA/'events.jsonl').open('a') as f:f.write(json.dumps(e)+'\n')
    return e
class API(http.server.BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def reply(self,data,status=200):
        body=json.dumps(data,ensure_ascii=False).encode();self.send_response(status);self.send_header('Content-Type','application/json; charset=utf-8');self.send_header('Cache-Control','no-store');self.end_headers();self.wfile.write(body)
    def do_GET(self):
        if self.headers.get('Host') not in ('127.0.0.1:8765','localhost:8765'):return self.reply({'error':'Invalid host'},403)
        if self.path=='/api/state':
            try:
                live=json.loads((DATA/'sensor-live.json').read_text())
                state['sensor']=live['sensor'] if time.time()-live['heartbeat']<4 else 'CLI monitor offline'
                state['ebpf']=live['events'] if time.time()-live['heartbeat']<4 else []
            except (OSError,ValueError):state['sensor']='เปิด sudo python3 monitor.py ใน CLI';state['ebpf']=[]
            return self.reply(state)
        if self.path not in ('/','/client','/server'):return self.reply({'error':'Not found'},404)
        body=(BASE/'index.html').read_text().replace('__TOKEN__',TOKEN).encode();self.send_response(200);self.send_header('Content-Type','text/html; charset=utf-8');self.end_headers();self.wfile.write(body)
    def do_POST(self):
        if self.headers.get('X-Lab-Token')!=TOKEN:return self.reply({'error':'Reload this page'},403)
        try:
            length=int(self.headers.get('Content-Length','0'))
            if length>8192:raise ValueError('Request too large')
            data=json.loads(self.rfile.read(length) or '{}')
            with LOCK:
                if self.path=='/api/setup':setup();out={'ok':True}
                elif not state['ready']:raise ValueError('กดเริ่มระบบก่อน')
                elif self.path=='/api/rules':
                    validate(data['rules']);old=state['rules'];state['ready']=False;state['rules']=data['rules']
                    try:policy();save();time.sleep(1);state['ready']=True
                    except Exception:state['rules']=old;raise
                    out={'ok':True}
                elif self.path=='/api/send':out=request(data['port'])
                else:return self.reply({'error':'Not found'},404)
            self.reply(out)
        except Exception as e:self.reply({'error':str(e)},400)
if __name__=='__main__':
    if (DATA/'config.json').exists():
        saved=json.loads((DATA/'config.json').read_text());validate(saved);state['rules']=saved
    print('Network Lab: http://localhost:8765',flush=True)
    http.server.ThreadingHTTPServer(('127.0.0.1',8765),API).serve_forever()
