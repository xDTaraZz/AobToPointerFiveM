<div align="center">

```
 █████   ██████  ██████      ██████      ██████  ████████ ██████
██   ██ ██    ██ ██   ██          ██     ██   ██    ██    ██   ██
███████ ██    ██ ██████       █████      ██████     ██    ██████
██   ██ ██    ██ ██   ██     ██          ██         ██    ██   ██
██   ██  ██████  ██████      ███████     ██         ██    ██   ██
```

### เปลี่ยน AOB To Pointer

![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![Arch](https://img.shields.io/badge/Arch-x64-7C3AED?style=for-the-badge)
![Dependencies](https://img.shields.io/badge/Dependencies-none-22C55E?style=for-the-badge)

<br>

[English](README.md) · **ไทย**

</div>

<br>

address แบบเต็มจะเปลี่ยนทุกครั้งที่เปิดเกมใหม่ และ offset ก็ขยับทุก gamebuild แต่ signature อยู่รอดทั้งสองอย่าง
เครื่องมือนี้เดินไปมาระหว่างสองฝั่ง — วาง AOB ได้ `Module.exe+OFFSET` หรือวาง address ก็ได้ AOB กลับมา
ไฟล์เดียว ไม่ต้องลงอะไร และอ่านอย่างเดียวไม่เขียนหน่วยความจำ

หา **FiveM** และ **RedM** ให้เอง รองรับ **ทุก gamebuild** ถ้ายังไม่เปิดเกมมันจะรอจนกว่าจะเจอ

<br>

## หน้าตา

```
        +- TARGET ---------------------------------------------------------+
        |  FiveM_b3095_GTAProcess.exe   build 3095                         |
        |  pid 14820   x64   0x7FF64C120000   100 MB                       |
        +------------------------------------------------------------------+

        > 48 8B 8B 88 01 00 00 F3 0F 10 40 2C

        100 MB   0.48s

        +- MATCH ----------------------------------------------------------+
        |  > FiveM_b3095_GTAProcess.exe+1A4F3C6                            |
        |  0x7FF64DB6F3C6    0x188[rbx]  0x2C[rax]                         |
        +------------------------------------------------------------------+
```

ผลลัพธ์ถูก copy ลง clipboard ให้อัตโนมัติทุกครั้ง

<br>

## วิธีรัน

ต้องใช้ Windows และ **Python 3.8+ แบบ 64-bit** ไม่ต้องลง library อะไรเพิ่ม

```bash
py main.py
```

ถ้าจะเจาะโปรเซสอื่น ใส่ชื่อต่อท้าย

```bash
py main.py FiveM_GTAProcess.exe
```

> [!TIP]
> ถ้าเปิดโปรเซสไม่ได้ ให้รัน terminal แบบ Run as Administrator

<br>

## การใช้งาน

ช่องเดียวใช้ได้ทั้งสองทาง ตัวโปรแกรมดูจากสิ่งที่พิมพ์เอง

**ใส่ไบต์ ได้ address** จะเว้นวรรค ใส่ comma ใส่ `0x` หรือใช้ wildcard `??` ก็ได้หมด

```
> 48 8B 8B 88 01 00 00 F3 0F 10 40 2C
> 48,8B,8B,88,01,00,00
> 48 8B 8B ?? ?? 00 00
```

**ใส่ address ได้ไบต์** มันจะต่อ signature ไปเรื่อยๆ จนเหลือจุดเดียวในโมดูล
แล้วใส่ `??` เฉพาะไบต์ที่จะขยับตอนเกมอัปเดต

```
> FiveM_b3095_GTAProcess.exe+1A4F3C6
> +1A4F3C6
> 0x7FF64DB6F3C6
```

<br>

## ตัวเลือกเสริม

พิมพ์ต่อท้ายไบต์ในบรรทัดเดียวกัน ไม่ใส่ก็ได้

| ตัวเลือก | ผล |
|:--|:--|
| `+2C` | บวก offset (hex) เข้าที่อยู่ที่ได้ |
| `rip 3:7` | ตาม `[rip+disp32]` ไปยังที่อยู่ที่มันชี้จริง |
| `chain 0x188 0x2C` | เดิน pointer chain แล้วโชว์ค่าจริง |
| `all` | สแกนทั้งโปรเซส แทนที่จะสแกนแค่โมดูลหลัก |

```
> 48 8B 05 ?? ?? ?? ??  rip 3:7
> 48 8B 8B 88 01 00 00  chain 0x188 0x2C
```

<br>

## เรื่อง offset

`48 8B 8B 88 01 00 00` คือ `mov rcx,[rbx+0x188]` ดังนั้น `0x188` เป็น offset ของ field จริงๆ
เอาไปต่อ pointer chain ได้เลย ส่วน offset ที่อิง `rsp` หรือ `rbp` จะถูกซ่อนไว้ เพราะเป็นตำแหน่งบน stack
ไม่ใช่ offset ในโครงสร้างข้อมูล

<br>

## หมายเหตุ

อ่านอย่างเดียว เปิดโปรเซสด้วยสิทธิ์ `PROCESS_VM_READ` ไม่มีการเขียน inject หรือ hook อะไรทั้งสิ้น
ทำมาเพื่องาน reverse engineering และ modding ส่วนจะเอาไปใช้กับเซิร์ฟเวอร์ไหนก็แล้วแต่กติกาของที่นั่น

<br>

---

<div align="center">

**สร้างโดย [xDTaraZz](https://github.com/xDTaraZz)** · MIT License

</div>