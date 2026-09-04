# คู่มือการตั้งค่า (Configuration Manual)

> 🌐 English: [CONFIGURATION.md](CONFIGURATION.md)

คู่มืออ้างอิงฉบับสมบูรณ์สำหรับไฟล์ตั้งค่าของ Softnix Log Agent ไฟล์ตั้งค่าเป็น
YAML ไฟล์เดียว (โดยทั่วไปคือ `agent.yaml`) ทุก section เป็น optional และจะใช้ค่า
default ตามที่ระบุไว้ด้านล่างหากไม่กำหนด

- **ตรวจสอบความถูกต้อง:** `softnix-log-agent validate --config agent.yaml`
- **นำการเปลี่ยนแปลงไปใช้:** แก้ไฟล์แล้ว reload (ปุ่ม **Save & Reload** บน web GUI,
  `POST /api/config/reload`, หรือส่ง `SIGHUP` บน Linux) — การ reload จะ validate
  ก่อนเสมอ และ rollback อัตโนมัติหากล้มเหลว
- **ไฟล์ตัวอย่าง:** [`examples/agent.yaml`](../examples/agent.yaml) (เต็ม) ·
  [`examples/minimal.yaml`](../examples/minimal.yaml) (ขั้นต่ำ) ·
  [`examples/windows.yaml`](../examples/windows.yaml) (Windows)

คีย์ที่ไม่รู้จักจะถูกปฏิเสธ (`deny_unknown_fields`) — พิมพ์ผิดจะ validate ไม่ผ่าน
แทนที่จะถูกเพิกเฉยเงียบ ๆ

## โครงสร้างระดับบนสุด

```yaml
agent:    { … }      # การตั้งค่าระดับ process
inputs:   { … }      # log มาจากไหน (files / syslog / eventlog)
pipeline: { … }      # ขั้น transform + enrich
buffer:   { … }      # คิวบนดิสก์ต่อปลายทาง
outputs:  [ … ]      # ส่ง log ไปที่ไหน
web:      { … }      # GUI / API สำหรับจัดการ
```

## ตัวแปรสภาพแวดล้อม (Environment variables)

อ้างอิงตัวแปรสภาพแวดล้อมได้ทุกที่ในไฟล์:

| รูปแบบ | ความหมาย |
|---|---|
| `${VAR}` | **บังคับ** — validate ไม่ผ่านหาก `VAR` ไม่ถูกตั้งค่า |
| `${VAR:-default}` | **ไม่บังคับ** — ใช้ `default` เมื่อ `VAR` ไม่ถูกตั้งค่า |

การแทนค่าเป็นแบบ **text** และเกิดขึ้น **ก่อน** parse YAML (มีผลกับ comment ด้วย)
ควรใช้รูปแบบ `:-` เสมอสำหรับตัวแปรที่อาจไม่ถูกตั้งค่า

```yaml
enrich:
  environment: ${ENVIRONMENT:-production}
```

ห้ามใช้รูปแบบ `:-` (default) กับ `web.auth_token` (หรือ secret อื่นใด):
`${WEB_TOKEN:-}` เมื่อไม่ได้ตั้งค่า `WEB_TOKEN` จะขยายเป็น string ว่าง ซึ่งตอนนี้
agent จะถือว่า "ยังไม่ได้ตั้งค่า" แล้วสร้าง token ใหม่ให้แทน — แต่ string ว่างไม่ใช่
ค่าที่ปลอดภัยสำหรับ secret จริง ให้ใช้รูปแบบบังคับแทน เพื่อให้ validate ล้มเหลว
ทันทีหากลืมตั้งค่าตัวแปร:

```yaml
web:
  auth_token: ${WEB_TOKEN}
```

---

## `agent`

การตั้งค่าระดับ process

| คีย์ | ชนิด | ค่า default | คำอธิบาย |
|---|---|---|---|
| `data_dir` | path | `data` | โฟลเดอร์หลักเก็บ state (offset ไฟล์, bookmark ของ Event Log) และคิวบนดิสก์ การติดตั้งแบบ service จะตั้งเป็น path เต็ม (`/var/lib/softnix-log-agent`, `C:\ProgramData\Softnix\LogAgent`) |
| `log_level` | string | `info` | ระดับ log ของตัว agent เอง: `trace`, `debug`, `info`, `warn`, `error` |

```yaml
agent:
  data_dir: /var/lib/softnix-log-agent
  log_level: info
```

---

## `inputs`

มี input 3 ตระกูล แต่ละตระกูลเป็น list กำหนดได้ไม่จำกัดจำนวน

```yaml
inputs:
  files:    [ … ]
  syslog:   [ … ]
  eventlog: [ … ]   # Windows เท่านั้น
```

ทุก input ต้องมี `id` ที่ไม่ซ้ำ (ใช้ namespace ร่วมกับ outputs — ห้ามซ้ำกัน)

### `inputs.files`

ตามอ่านไฟล์ในเครื่อง รองรับ glob discovery และการจัดการ rotation

| คีย์ | ชนิด | default | คำอธิบาย |
|---|---|---|---|
| `id` | string | — (บังคับ) | ตัวระบุที่ไม่ซ้ำ |
| `paths` | list | — (บังคับ) | glob pattern รองรับ `*`, recursive `**` และ Windows path (`C:\Logs\*.log`) |
| `exclude` | list | `[]` | glob pattern ที่ต้องการข้าม |
| `poll_interval_ms` | int | `500` | ช่วงเวลา poll การเปลี่ยนแปลง/ค้นหาไฟล์ ขั้นต่ำ `50` ยิ่งต่ำยิ่งสด แต่กิน CPU มากขึ้นเล็กน้อย |
| `read_from_start` | bool | `false` | ครั้งแรกที่รัน อ่านเนื้อหาเดิมตั้งแต่ต้นไฟล์ ค่า default จะข้ามเนื้อหาเดิมและอ่านเฉพาะบรรทัดใหม่ (ไฟล์ที่ถูกค้นพบ *ภายหลัง* จะอ่านตั้งแต่ต้นเสมอ) |
| `parser` | object | `mode: raw` | ดู [Parsers](#parsers) |
| `source_type` | string | `file` | แทนค่า field `source_type` ของ event ที่สร้าง |

```yaml
inputs:
  files:
    - id: app-logs
      paths:
        - /var/log/*.log
        - /app/logs/**/*.log
      exclude: ["**/*.gz"]
      poll_interval_ms: 500
      read_from_start: false
      parser: { mode: json }
```

**Rotation:** รองรับ rename rotation, copy-truncate, truncation และการสร้างไฟล์ใหม่
offset ถูกเก็บข้าม restart บน Windows การระบุตัวตนไฟล์ใช้ creation time บวกกับ hash
ของบรรทัดแรก (ดู [Known limitations](../README.md#known-limitations))

### `inputs.syslog`

รับ syslog ผ่านเครือข่าย

| คีย์ | ชนิด | default | คำอธิบาย |
|---|---|---|---|
| `id` | string | — (บังคับ) | ตัวระบุที่ไม่ซ้ำ |
| `protocol` | enum | `udp` | `udp`, `tcp`, หรือ `tls` |
| `bind` | IP | `0.0.0.0` | address ที่จะ listen |
| `port` | int | — (บังคับ) | พอร์ต (1–65535) |
| `format` | enum | `auto` | `auto`, `rfc3164`, `rfc5424`, `json`, `raw` — `auto` ลองตามลำดับ RFC5424 → RFC3164 → JSON → raw |
| `tls` | object | — | บังคับเมื่อ `protocol: tls` (ดูด้านล่าง) |
| `source_type` | string | `syslog` | แทนค่า `source_type` ของ event |
| `keep_raw_message` | bool | `false` | เก็บบรรทัดต้นฉบับทั้งบรรทัด (รวม PRI, timestamp, hostname, tag) ไว้ใน `raw_message` ก่อนเวอร์ชันนี้ค่านี้เปิดอยู่เสมอโดยปริยาย — `message` (เนื้อหาที่ parse แล้ว) กับ `raw_message` สำหรับ syslog นั้นต่างกันจริง ดังนั้นการปิดค่านี้คือการสูญเสียข้อมูลจริง ไม่ใช่แค่การประหยัด — เปิดใช้หากต้องการบรรทัดต้นฉบับ (สำหรับ forensics หรือ SIEM ปลายทางที่ parse ข้อความดิบเอง) ทำให้หน่วยความจำ การใช้ queue และขนาดข้อมูลที่ส่งต่อเหตุการณ์เพิ่มเป็นสองเท่า |

**ตัวเลือก `tls` (ฝั่ง server)** — บังคับสำหรับ `protocol: tls`:

| คีย์ | ชนิด | คำอธิบาย |
|---|---|---|
| `cert` | path | ใบรับรอง server (PEM) |
| `key` | path | private key ของ server (PEM) |
| `client_ca` | path | CA bundle สำหรับตรวจสอบใบรับรองฝั่ง client — เปิดใช้ **mutual TLS** |

```yaml
inputs:
  syslog:
    - id: udp514
      protocol: udp
      port: 514
    - id: tls6514
      protocol: tls
      port: 6514
      tls:
        cert: /etc/softnix-log-agent/tls/server.crt
        key:  /etc/softnix-log-agent/tls/server.key
        # client_ca: /etc/softnix-log-agent/tls/clients-ca.crt   # mTLS
```

> syslog input แบบ TCP/TLS ใช้ newline framing เท่านั้น

### `inputs.eventlog` (Windows เท่านั้น)

เก็บ Windows Event Log channel แบบ native ผ่าน `wevtapi` บนแพลตฟอร์มที่ไม่ใช่
Windows การตั้งค่า eventlog จะถูกเพิกเฉยพร้อมคำเตือนตอน validate

| คีย์ | ชนิด | default | คำอธิบาย |
|---|---|---|---|
| `id` | string | — (บังคับ) | ตัวระบุที่ไม่ซ้ำ |
| `channels` | list | — (บังคับ, ≥1) | ชื่อ channel: `Application`, `System`, `Security` หรือ custom (เช่น `Microsoft-Windows-Sysmon/Operational`) |
| `query` | string | `*` | ตัวกรอง XPath สำหรับแต่ละ channel `*` = ทุก event |
| `read_existing` | bool | `false` | ครั้งแรกที่รัน (ยังไม่มี bookmark) อ่าน event เดิมตั้งแต่ record เก่าสุด ค่า default เก็บเฉพาะ event ที่เข้ามาหลังเริ่มทำงาน |
| `source_type` | string | `eventlog` | แทนค่า `source_type` ของ event |
| `keep_raw_message` | bool | `false` | เก็บ Event XML ฉบับเต็ม (2-4 KB) ไว้ใน `raw_message` ก่อนเวอร์ชันนี้ค่านี้เปิดอยู่เสมอโดยปริยาย `message` มีข้อความที่มนุษย์อ่านได้อยู่แล้ว จึงจำเป็นเฉพาะกรณีที่ต้องใช้ XML ดิบต่อ ทำให้หน่วยความจำ การใช้ queue และขนาดข้อมูลที่ส่งต่อเหตุการณ์เพิ่มเป็นสองเท่า |

```yaml
inputs:
  eventlog:
    - id: winevents
      channels: [Application, System, Security]
      # เฉพาะ Critical/Error/Warning:
      query: "*[System[(Level=1 or Level=2 or Level=3)]]"
      read_existing: false
```

**พฤติกรรมและข้อควรทราบ:**

- ความคืบหน้าถูก checkpoint ด้วย **bookmark** ของ Event Log เก็บไว้ใต้
  `agent.data_dir` → ส่งแบบ at-least-once และ resume ต่อได้หลัง restart
- ข้อความที่มนุษย์อ่านได้ถูก render จาก metadata ของ publisher หาก message DLL
  ของ provider ไม่มี จะ fallback ไปใช้ `EventData` ที่ต่อกัน ส่วน XML เต็มจะถูก
  เก็บไว้ใน `raw_message` เฉพาะเมื่อตั้งค่า `keep_raw_message: true` เท่านั้น
- การ map field: `Level` → `severity`, `Provider` → `application`,
  `Computer` → `hostname` พร้อม `event_id`, `channel`, `record_id`, `keywords`
  และแต่ละรายการใน `EventData` เป็น `data_<Name>`
- การอ่าน channel **`Security`** ต้องมีสิทธิ์สูง — Windows Service รันเป็น
  LocalSystem ซึ่งเพียงพอแล้ว

### Parsers

ใช้โดย `inputs.files[].parser` ส่วน syslog input จะ parse ผ่าน `format` ของตัวเอง

| `mode` | คำอธิบาย | คีย์ที่เกี่ยวข้อง |
|---|---|---|
| `raw` *(default)* | เก็บบรรทัดเป็น `message` ไม่ parse | — |
| `json` | parse แต่ละบรรทัดเป็น JSON object เข้า fields | — |
| `kv` | parse คู่ `key=value` | `pair_separator` (default เว้นวรรค), `kv_separator` (default `=`) |
| `regex` | ดึง named capture group เข้า fields | `pattern` (บังคับ), `timestamp_format` |
| `syslog` | parse บรรทัดเป็น syslog (RFC5424/RFC3164) | — |

| คีย์ | ชนิด | default | คำอธิบาย |
|---|---|---|---|
| `mode` | enum | `raw` | หนึ่งในข้างต้น |
| `pattern` | string | — | regex ที่มี named group เช่น `(?P<status>\d+)` บังคับสำหรับ `regex` |
| `pair_separator` | string | `" "` | ตัวคั่นระหว่างคู่ (`kv`) |
| `kv_separator` | string | `=` | ตัวคั่นระหว่าง key กับ value (`kv`) |
| `timestamp_format` | string | — | รูปแบบ `chrono` สำหรับ parse group ชื่อ `timestamp` เช่น `%d/%b/%Y:%H:%M:%S %z` |
| `keep_raw_message` | bool | `false` | เก็บบรรทัดก่อน parse ไว้ใน `raw_message` แม้จะเหมือนกับ `message` ทุกตัวอักษร (เช่น `mode: raw`) ก่อนเวอร์ชันนี้ค่านี้เปิดอยู่เสมอโดยปริยาย — `Event::new` เก็บเนื้อหาซ้ำสองครั้งโดยไม่มีเงื่อนไข ทำให้หน่วยความจำ การใช้ queue และขนาดข้อมูลที่ส่งต่อเหตุการณ์เพิ่มเป็นสองเท่าโดยไม่มีประโยชน์ภายใต้ `mode: raw` ตั้งเป็น `true` เพื่อคืนพฤติกรรมเดิม หรือเพื่อเก็บข้อความก่อน parse ควบคู่กับ `message` ที่ parse แล้วภายใต้ `json`/`kv`/`regex`/`syslog` |

```yaml
parser:
  mode: regex
  pattern: '^(?P<remote>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\d+) (?P<bytes>\d+)'
  timestamp_format: "%d/%b/%Y:%H:%M:%S %z"
```

---

## `pipeline`

ทำงานหลัง parse ตามลำดับ: **transforms** แล้วจึง **enrich**

```yaml
pipeline:
  transforms: [ … ]
  enrich:     { … }
```

### `pipeline.transforms`

list ที่มีลำดับ แต่ละขั้นมี `type` ขั้นที่มีเงื่อนไข `when` จะทำงานเฉพาะเมื่อเงื่อนไข
เป็นจริง (ดู [Conditions](#conditions))

| `type` | คีย์ | ผลลัพธ์ |
|---|---|---|
| `add_field` | `field`, `value`, `when?` | ตั้งค่า field เป็นค่าคงที่ |
| `remove_field` | `field`, `when?` | ลบ field |
| `rename_field` | `from`, `to`, `when?` | เปลี่ยนชื่อ field |
| `convert` | `field`, `to`, `when?` | แปลงชนิด field — `to`: `int`, `float`, `string`, `bool` |
| `mask` | `field`, `pattern`, `replacement?`, `when?` | แทนค่าด้วย regex ภายใน field — `replacement` default `****` **การ mask `message` จะ mask `raw_message` ด้วยหากมีอยู่** (เฉพาะเมื่อ `keep_raw_message: true`) |
| `drop` | `when` *(บังคับ)* | ทิ้ง event ที่ตรง `when` |
| `keep` | `when` *(บังคับ)* | เก็บเฉพาะ event ที่ตรง `when` ที่เหลือทิ้ง |

```yaml
pipeline:
  transforms:
    - type: add_field
      field: team
      value: platform
    - type: convert
      field: status
      to: int
    - type: mask
      field: message
      pattern: '\b\d{13,16}\b'
      replacement: "[REDACTED]"
    - type: drop
      when: { field: message, op: contains, value: "health-check" }
    - type: add_field
      field: alert
      value: true
      when: { field: severity, op: lt, value: 3 }
```

### Conditions

ใช้กับ `when` ใน transforms และการ route ของ output

```yaml
when: { field: <ชื่อ>, op: <operator>, value: <ค่า> }
```

| `op` | ต้องมี `value` | ตรงเมื่อ… |
|---|---|---|
| `eq` | ใช่ | field เท่ากับ value |
| `ne` | ใช่ | field ไม่เท่ากับ value |
| `contains` | ใช่ | field (string) มี value อยู่ |
| `matches` | ใช่ | field (string) ตรงกับ regex ใน value |
| `gt` | ใช่ | field (ตัวเลข) มากกว่า value |
| `lt` | ใช่ | field (ตัวเลข) น้อยกว่า value |
| `exists` | ไม่ | มี field นี้อยู่ |
| `not_exists` | ไม่ | ไม่มี field นี้ |

`field` เป็น field ใดก็ได้ของ event — แบบ core (`message`, `severity`, `facility`,
`hostname`, `application`, `source`, `source_type`, `process_id`, …) หรือ field
ที่สร้างโดย parser/transform/enrich

### `pipeline.enrich`

เพิ่ม metadata คงที่/ของ host ให้ทุก event โดยจะไม่ทับ field ที่มีอยู่แล้ว

| คีย์ | ชนิด | default | คำอธิบาย |
|---|---|---|---|
| `hostname` | bool | `true` | เพิ่ม hostname ของเครื่อง (หาก event ยังไม่มี) |
| `os_info` | bool | `true` | เพิ่ม `os` (ชื่อ + arch) |
| `agent_version` | bool | `true` | ติด version ของ collector |
| `local_ip` | bool | `false` | เพิ่ม local IP ที่ตรวจพบ |
| `environment` | string | — | เช่น `production` |
| `site` | string | — | เช่น `dc-bkk-1` |
| `tenant` | string | — | ตัวระบุ tenant |
| `customer` | string | — | ตัวระบุลูกค้า |
| `tags` | list | `[]` | tag อิสระ |
| `fields` | map | `{}` | key/value เพิ่มเติมตามต้องการ |

```yaml
pipeline:
  enrich:
    hostname: true
    os_info: true
    local_ip: true
    environment: ${ENVIRONMENT:-production}
    site: dc-bkk-1
    tenant: softnix
    tags: [edge, th]
    fields: { rack: r12 }
```

---

## `buffer`

คิวบนดิสก์ที่ปลอดภัยต่อ crash ต่อปลายทาง คั่นระหว่าง pipeline กับ output แต่ละตัว

| คีย์ | ชนิด | default | คำอธิบาย |
|---|---|---|---|
| `dir` | path | `<data_dir>/queue` | โฟลเดอร์คิว |
| `max_size_mb` | int | `1024` | ขนาดสูงสุดบนดิสก์ **ต่อปลายทาง** |
| `segment_size_mb` | int | `8` | ขนาดไฟล์ segment แต่ละไฟล์ |
| `full_policy` | enum | `block` | พฤติกรรมเมื่อคิวเต็ม (ด้านล่าง) |

**`full_policy`:**

| ค่า | พฤติกรรม |
|---|---|
| `block` | ไม่ทิ้ง event ตราบใดที่ยังมีที่ว่าง โดย "ที่ว่าง" คือคิวบนดิสก์ของปลายทางนั้นเอง (`max_size_mb`) บวกกับบัฟเฟอร์ในหน่วยความจำขนาดเล็ก (~4096 event) ที่ช่วยรองรับ burst ช่วงสั้น ๆ และการรอ lock ของคิวบนดิสก์ — ไม่ใช่ input หยุดอ่าน เมื่อทั้งสองเต็มแล้ว event ใหม่สำหรับปลายทางนั้นจะถูกทิ้ง (นับแยกต่อปลายทางใน `agent_router_shed_total` พร้อม log) แทนที่จะไปหยุดปลายทางอื่น, pipeline, หรือ input ใด ๆ เมื่อมีการ reload config หรือหยุด agent แบบ graceful ระบบจะบังคับส่ง event ที่ยังค้างอยู่ในบัฟเฟอร์ในหน่วยความจำทั้งหมดเข้าคิวบนดิสก์ของปลายทางแทนการทิ้ง — ยกเว้นกรณีที่คิวบนดิสก์ของปลายทางนั้นเต็มอยู่แล้วในขณะนั้น ซึ่งไม่มีที่ว่างเหลือให้เก็บ event เหล่านั้นอีก จึงยังถูกนับเป็น dropped (`agent_events_dropped_total`) |
| `drop_oldest` | ทิ้ง event เก่าสุดเพื่อให้มีที่ว่าง — เน้นข้อมูลใหม่ |
| `drop_newest` | ปฏิเสธ event ใหม่เมื่อเต็ม — เน้นเก็บประวัติ |

> การประมาณขนาด: ความจุรองรับช่วงปลายทางล่ม ≈ อัตรา event × ขนาดเฉลี่ยต่อ event × ระยะเวลาที่ล่ม

```yaml
buffer:
  max_size_mb: 1024
  segment_size_mb: 8
  full_policy: block
```

---

## `outputs`

list ของปลายทาง แต่ละ event จะถูก route ไปยังทุก output ที่เงื่อนไข `when` ตรง
(หรือทุก output หากไม่มี `when`) ภายใต้กลไก failover

| คีย์ | ชนิด | default | คำอธิบาย |
|---|---|---|---|
| `id` | string | — (บังคับ) | ตัวระบุที่ไม่ซ้ำ |
| `type` | enum | — (บังคับ) | `syslog` หรือ `stdout` |
| `address` | `host:port` | — | บังคับสำหรับ `syslog` |
| `protocol` | enum | `udp` | `udp`, `tcp`, `tls` (syslog) |
| `format` | enum | `rfc5424` | `rfc5424`, `rfc3164`, `json`, `raw` |
| `framing` | enum | `newline` | `newline` หรือ `octet_counting` (TCP/TLS) |
| `tls` | object | — | ตัวเลือก TLS ฝั่ง client (ด้านล่าง) |
| `when` | condition | — | route เฉพาะ event ที่ตรงมาที่นี่ |
| `failover_for` | string | — | รับ traffic เฉพาะตอน output ที่ระบุไม่ healthy |
| `retry` | object | ดูด้านล่าง | การปรับจูนการส่ง/retry |
| `full_policy` | enum | — (ใช้ค่า `buffer.full_policy` ถ้าไม่ระบุ) | override `buffer.full_policy` เฉพาะปลายทางนี้ — ดูหัวข้อ [`buffer`](#buffer) ด้านบน |

**ตัวเลือก `tls` (ฝั่ง client):**

| คีย์ | ชนิด | default | คำอธิบาย |
|---|---|---|---|
| `ca` | path | system roots | CA bundle สำหรับตรวจสอบ server |
| `cert` | path | — | ใบรับรอง client สำหรับ mTLS |
| `key` | path | — | private key ของ client สำหรับ mTLS |
| `verify` | bool | `true` | ตรวจสอบใบรับรอง server **อย่าปิดใน production** |
| `server_name` | string | — | แทนค่า SNI / hostname ในใบรับรอง |

**ตัวเลือก `retry`:**

| คีย์ | ชนิด | default | คำอธิบาย |
|---|---|---|---|
| `initial_backoff_ms` | int | `500` | ดีเลย์ retry ครั้งแรก (เพิ่มเป็น 2 เท่าทุกครั้งที่ล้มเหลว) |
| `max_backoff_ms` | int | `30000` | ดีเลย์ retry สูงสุด |
| `batch_size` | int | `200` | จำนวน event ต่อ batch ยิ่งมาก throughput ยิ่งสูง แต่หน้าต่างซ้ำตอน crash ก็ใหญ่ขึ้น |

**หมายเหตุเรื่อง format/transport:**

- output `rfc5424` แนบ field enrich/custom ในส่วน STRUCTURED-DATA
- `json` ส่ง event เต็มรวมถึง `raw_message`
- UDP ส่งหนึ่ง event ต่อหนึ่ง datagram event ที่ใหญ่เกิน ~64 KB จะถูก drop
  (นับใน `events_dropped`) เพื่อไม่ให้ไปอุดคิว

```yaml
outputs:
  - id: siem-primary
    type: syslog
    protocol: tls
    address: siem.example.com:6514
    format: rfc5424
    tls:
      ca:   /etc/softnix-log-agent/tls/siem-ca.crt
      cert: /etc/softnix-log-agent/tls/agent.crt
      key:  /etc/softnix-log-agent/tls/agent.key
    retry: { batch_size: 200, max_backoff_ms: 30000 }

  - id: siem-backup
    type: syslog
    protocol: tcp
    address: siem-backup.example.com:514
    format: rfc5424
    failover_for: siem-primary

  - id: alerts
    type: syslog
    protocol: udp
    address: alerting.example.com:514
    when: { field: severity, op: lt, value: 4 }
```

---

## `web`

GUI สำหรับจัดการและ JSON/metrics API ในตัว

| คีย์ | ชนิด | default | คำอธิบาย |
|---|---|---|---|
| `enabled` | bool | `true` | เปิดให้บริการ GUI/API |
| `bind` | IP | `127.0.0.1` | address ที่ listen ค่า default คือ localhost เท่านั้น |
| `port` | int | `8080` | พอร์ตที่ listen |
| `auth_token` | string | — | bearer token ที่ทุก request ของ API ต้องส่งมา |

หากต้องการเปิด GUI ออกนอก localhost ให้ตั้ง `bind: 0.0.0.0` **และ** `auth_token`
(มิฉะนั้น agent จะเตือนตอนเริ่มทำงาน) จากนั้น client ต้องส่ง
`Authorization: Bearer <token>` (หรือ `X-Auth-Token`) แนะนำให้ใช้ firewall หรือ
SSH tunnel — GUI เป็น HTTP ธรรมดา

```yaml
web:
  enabled: true
  bind: 127.0.0.1
  port: 8080
  # auth_token: replace-with-a-long-random-secret
```

---

## สูตรใช้งานที่พบบ่อย (Common recipes)

**เครื่อง Windows → SIEM ส่วนกลาง:**

```yaml
inputs:
  eventlog:
    - id: win
      channels: [Application, System, Security]
pipeline:
  enrich: { site: hq, environment: production }
outputs:
  - id: siem
    type: syslog
    protocol: tcp
    address: siem.corp.local:514
    format: rfc5424
```

**ตามอ่าน JSON app log, ปิดข้อมูลลับ, ส่งผ่าน TLS:**

```yaml
inputs:
  files:
    - id: app
      paths: ["/app/logs/*.json"]
      parser: { mode: json }
pipeline:
  transforms:
    - type: mask
      field: message
      pattern: '\b\d{13,16}\b'
      replacement: "[REDACTED]"
outputs:
  - id: siem
    type: syslog
    protocol: tls
    address: siem.example.com:6514
    format: rfc5424
    tls: { ca: /etc/softnix/ca.crt }
```

**ตัด noise เก็บเฉพาะ error:**

```yaml
pipeline:
  transforms:
    - type: keep
      when: { field: severity, op: lt, value: 5 }
```

ดู [OPERATIONS.md](OPERATIONS.md) สำหรับแนวทางการ reload, monitoring และการปรับจูน
