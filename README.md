# PS5 WebKit Autoloader — ESP8266 Smart-OLED build

Ready-to-flash firmware for [owendswang/ps5-webkit-autoloader-esp32](https://github.com/owendswang/ps5-webkit-autoloader-esp32) targeting **ESP8266 boards with a built-in 0.96" OLED**, with an on-screen status UI.

Shared via [issue #4](https://github.com/owendswang/ps5-webkit-autoloader-esp32/issues/4).

## File

| File | Description |
|---|---|
| `ps5-autoloader-smartUI-v1.0-esp8266.bin` | Merged flash image (firmware + filesystem), flash at `0x0` |
| `esp8266-arduino.ino` | Full sketch source (HTTP-only + OLED UI + JB tracker) |

## Tested board

**ideaspark ESP8266 0.96" OLED VR 2.1** (ESP-12E, 4MB flash, CH340G, USB-C)
- SSD1306 128x64 OLED @ I2C `0x3C`, **SDA = GPIO12 (D6), SCL = GPIO14 (D5)**
- Display is auto-detected at boot across common pin pairs

## What the OLED shows (3 pages, rotates every 6 s)

1. **Dashboard** — jailbreak progress stage + progress bar:
   `WAIT → client online → browser → installer → payload UI → FW seen → exploit run → kernel/rop`
   plus PS5 MAC (Sony OUI detection), AP SSID, client count, request/error counters
2. **Live log** — last 4 events (joins, stage changes, requests, 404s)
3. **System** — chip ID, AP MAC, free heap, uptime, connected client MAC

Stage inference is monotonic per session and resets ~2 s after the client disconnects.

## Flash

```bash
esptool.py --chip esp8266 --port PORT --baud 115200 \
  write_flash --flash_mode dout --flash_freq 40m --flash_size 4MB \
  0x0 ps5-autoloader-smartUI-v1.0-esp8266.bin
```

No erase required. Image covers `0x000000–0x3FA000` (app @ `0x0`, LittleFS @ `0x100000` size `0x2FA000`) and deliberately does not touch RF calibration @ `0x3FC000`.

## Build notes

- HTTP-only (BearSSL removed) — fits ESP8266 RAM, fine for local exploit serving
- **Important:** on the 4M3M layout LittleFS must be at `0x100000` (`0x100000 + 0x2FA000 = 0x3FA000`). Flashing the FS at `0x110000` ends at `0x400000`, overwrites RF cal, and the board crash-loops with `Exception 29` in WiFi init.
- Built with arduino-cli, esp8266 core 3.1.2, ThingPulse OLED driver 4.6.2
- FQBN: `esp8266:esp8266:generic:eesz=4M3M,FlashMode=dout,ssl=basic,xtal=80,...`
