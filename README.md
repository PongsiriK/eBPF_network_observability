# eBPF Network Observability

เดโมตรวจสอบการเชื่อมต่อ TCP ของ Docker container แบบ real time ด้วย eBPF พร้อมหน้าจอสำหรับกำหนดพอร์ตและทดสอบการเชื่อมต่อ

ระบบใช้ **bpftrace/eBPF สำหรับตรวจจับ**, Python สำหรับแสดงผลและประเมินนโยบาย และ **iptables สำหรับบล็อก** โดยกฎบล็อกอยู่ใน network namespace ของ client container

```text
Client UI → client container → firewall → server container
                       │
                       └→ eBPF → Python monitor ใน terminal
```

| นโยบาย | ผลการทดสอบ |
| --- | --- |
| ALLOW | ส่งผ่านเมื่อ server เปิดรับพอร์ตนั้น |
| ALERT | ส่งผ่านและแสดงการแจ้งเตือน |
| BLOCK | iptables ปฏิเสธการเชื่อมต่อก่อนถึง server |

## สิ่งที่ต้องมี

- Ubuntu บน Linux หรือ WSL 2 พร้อม Python 3 และ `bpftrace`
- Docker Engine ที่รันอยู่บน Linux kernel เดียวกับ eBPF monitor และผู้ใช้สามารถเข้าถึง Docker ได้
- สิทธิ์ `sudo` สำหรับ monitor และการตั้งค่าตามตัวอย่าง
- การเชื่อมต่ออินเทอร์เน็ตขณะ build Docker image ครั้งแรก เพื่อดาวน์โหลด dependencies

ตัวอย่างติดตั้ง `bpftrace` บน Ubuntu:

```bash
sudo apt update
sudo apt install -y bpftrace
```

ตรวจสอบสภาพแวดล้อม:

```bash
uname -r
python3 --version
bpftrace --version
sudo docker info
test -r /sys/kernel/btf/vmlinux && echo 'Kernel BTF available'
```

Docker Desktop อาจใช้ Linux environment แยกจาก Ubuntu WSL ทำให้ monitor มองไม่เห็น PID/cgroup ของ container ใน `/proc` แม้ Docker CLI จะใช้งานได้ ควรตรวจว่า Docker Engine กับ monitor อยู่บน kernel และมองเห็น cgroup ชุดเดียวกัน

## วิธีรัน

หากยังไม่มี repository ให้ clone ก่อน:

```bash
git clone https://github.com/PongsiriK/eBPF_network_observability.git
cd eBPF_network_observability
```

ถ้ามี repository อยู่แล้ว ให้ `cd` ไปยังโฟลเดอร์ที่มี `app.py` แทน

**Terminal 1 — เริ่มเว็บ backend**

```bash
sudo python3 -u app.py
```

เปิดทิ้งไว้ แล้วเปิด [หน้า Server](http://localhost:8765/server) ใน browser กด **เริ่มระบบ Docker** รอจนพร้อม ระบบจะ build image สร้าง network และ container เดโม จากนั้นตั้งพอร์ตและนโยบาย แล้วกด **ใช้การตั้งค่า**

**Terminal 2 — เริ่ม eBPF monitor**

เปิด terminal อีกหน้าต่างและเข้าโฟลเดอร์ repository เดียวกัน:

```bash
sudo python3 -u monitor.py
```

รอข้อความ `SENSOR: live` และเปิดหน้าต่างนี้ทิ้งไว้เพื่อดู TCP connect events กด Ctrl+C เพื่อหยุด monitor

**ทดสอบผ่าน UI**

เปิด [หน้า Client](http://localhost:8765/client) กรอกพอร์ตแล้วกด **ส่ง request** ผลจะปรากฏหลังส่ง ส่วนหน้า Server แสดงประวัติและระบุว่าพบ request ใน log ของ server หรือไม่ ค่าเริ่มต้นในโค้ดคือ 8000 ALLOW, 9000 ALERT และ 8080 BLOCK; หากมี `data/config.json` อยู่ โปรแกรมจะอ่านค่าที่บันทึกไว้แทน

**ทดสอบจาก CLI**

```bash
docker exec codex-network-lab-client python -c "import urllib.request; r=urllib.request.urlopen('http://codex-network-lab-server:8000/cli-test',timeout=3); print('HTTP',r.status); print(r.read().decode())"
```

เปลี่ยน `8000` เป็นพอร์ตที่ต้องการ คำสั่งนี้ส่งจาก client container จึงอยู่ในขอบเขตของ monitor และ firewall โดยจะไม่สร้างรายการในตาราง request ของ UI แต่ server จะบันทึกคำขอที่ได้รับใน `data/received.jsonl`

## ไฟล์หลัก

| ไฟล์ | หน้าที่ |
| --- | --- |
| `app.py` | Backend สำหรับ UI สร้าง Docker resources ตั้ง firewall และมีฟังก์ชันเริ่ม sensor |
| `monitor.py` | เรียก sensor และแสดง eBPF events ใน terminal |
| `service.py` | HTTP server ใน container เปิด listener ตามพอร์ตที่กำหนด |
| `index.html` | หน้า Server และ Client |
| `trace.bt` | bpftrace program ที่สร้างใหม่เมื่อเริ่ม monitor ตาม cgroup ของ client |
| `Dockerfile` | สร้าง image สำหรับเดโมและ firewall helper |
| `verify_ui.py` | สคริปต์ตรวจการทำงานของ UI backend |

`verify_ui.py` ส่งคำขอจริงและเปลี่ยนกฎชั่วคราวระหว่างทดสอบ จึงควรรันเฉพาะในช่วงทดลอง โดยเปิด backend, Docker และ monitor ไว้ก่อน:

```bash
python3 verify_ui.py
```

## การหยุดและข้อจำกัด

- กด Ctrl+C ใน terminal ของ `monitor.py` และ `app.py` เพื่อหยุดแต่ละโปรแกรม Container ยังอยู่ กฎ firewall ยังมีผลจนกว่าจะเปลี่ยนกฎหรือ namespace ของ container ถูกทำลาย
- หาก restart หรือสร้าง client container ใหม่ ให้เริ่มระบบจาก UI ใหม่ แล้ว restart monitor เพื่ออ่าน cgroup ID ใหม่
- ตรวจเฉพาะ TCP IPv4 connect ของ client container ที่กำหนด ไม่ครอบคลุมโปรแกรม Windows, UDP หรือ IPv6
- ค่า `kernel_return=0` ไม่ยืนยันว่า HTTP สำเร็จ ให้ดูผล HTTP และ log ของ server ประกอบ
- ALERT เป็นการประเมินใน Python; BLOCK ใช้ iptables ไม่ใช่ eBPF enforcement ระบบนี้เป็นเดโม ไม่ใช่ firewall สำหรับ production
- Client และ Server ใช้ Docker network แบบ internal; เดโมไม่ได้ส่ง request ออกอินเทอร์เน็ต
- ประวัติและการตั้งค่าอยู่ใน `data/` โปรดตรวจเนื้อหาก่อนแชร์ repository หรือไฟล์ log

## งานวิจัยอ้างอิง

ต้นแบบนี้ประยุกต์บางแนวคิดจากระบบ Sauron ใน D. Soldani และคณะ, “eBPF: A New Approach to Cloud-Native Observability, Networking and Security for Current (5G) and Future Mobile Networks (6G and Beyond),” *IEEE Access*, vol. 11, 2023. [DOI: 10.1109/ACCESS.2023.3281480](https://doi.org/10.1109/ACCESS.2023.3281480) ไม่ใช่การทำซ้ำระบบหรือผลการทดลองทั้งหมดของงานวิจัย
