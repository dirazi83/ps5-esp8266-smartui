#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <DNSServer.h>
#include <ESP8266WebServer.h>
#include <LittleFS.h>
#include <Wire.h>

// ================= OLED DRIVER SELECT =================
// 0 = SSD1306 (0.96" 128x64, most common)
// 1 = SH1106 (1.3" 128x64)
#define OLED_DRIVER_SH1106 0

#if OLED_DRIVER_SH1106
#include <SH1106Wire.h>
typedef SH1106Wire OledDriver;
#else
#include <SSD1306Wire.h>
typedef SSD1306Wire OledDriver;
#endif

extern "C" {
#include <user_interface.h>
}

static const char *FW_VER = "v1.0";
static const char *AP_SSID = "ESP32_PORTAL";
static const char *AP_PASSWORD = "12345678";
static const char *PORTAL_REDIRECT_URL = "http://192.168.4.1/";
static const char *PAYLOAD_MIRROR_PREFIX = "/ps5-payloads-mirror/";
static const char *PAYLOAD_LOCAL_PREFIX = "/pldmrr/";
static const IPAddress AP_IP(192, 168, 4, 1);
static const IPAddress AP_GATEWAY(192, 168, 4, 1);
static const IPAddress AP_SUBNET(255, 255, 255, 0);
static const char *NO_CACHE_VALUE = "no-store, no-cache, must-revalidate, max-age=0";

DNSServer dnsServer;
ESP8266WebServer webServer(80);

static String normalizePath(const String &uri);

// ============================================================
// JB TRACKER: PS5 connection + jailbreak progress inference
// ============================================================
enum JbStage {
    JB_WAIT = 0,       // nobody connected
    JB_ONLINE,         // station joined the AP
    JB_BROWSER,        // HTTP/captive-portal traffic seen
    JB_INSTALLER,      // installer page served
    JB_PAYLOAD_UI,     // payload selector page touched
    JB_FW,             // firmware version seen in offsets/
    JB_EXPLOIT,        // exploit entry page / main js running
    JB_KERNEL,         // rop/kexp/syscalls/firmware payloads
    JB_STAGE_COUNT
};

struct JbTracker {
    uint8_t stage = JB_WAIT;
    uint8_t stations = 0;
    char ps5Mac[18] = {0};
    char fw[8] = {0};
    char exploit[12] = {0};
    bool isSony = false;
    bool sessionUp = false;
    uint32_t stageMs = 0;
    uint32_t lastReqMs = 0;
    uint32_t leftAt = 0;
    uint32_t reqCount = 0;
    uint32_t errCount = 0;
    char lastPath[40] = {0};
};
static JbTracker jb;

#define JB_LOG_LINES 8
#define JB_LOG_LEN 24
static char jbLog[JB_LOG_LINES][JB_LOG_LEN];
static uint8_t jbLogPos = 0;
static uint8_t jbLogCount = 0;

static const char *JB_STAGE_NAME[] = {
    "WAITING PS5", "PS5 ONLINE", "BROWSER", "INSTALLER",
    "PAYLOAD UI", "FW", "EXPLOIT RUN", "KERNEL PWN"
};

static uint32_t jbBootMs = 0;

static void fmtUp(char *buf, size_t n) {
    uint32_t s = (millis() - jbBootMs) / 1000;
    if (s < 3600) snprintf(buf, n, "%u:%02u", s / 60, s % 60);
    else snprintf(buf, n, "%u:%02u:%02u", s / 3600, (s / 60) % 60, s % 60);
}

static void jbLogAdd(const char *fmt, ...) {
    char msg[20];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    char up[10];
    fmtUp(up, sizeof(up));
    snprintf(jbLog[jbLogPos], JB_LOG_LEN, "%s %s", up, msg);
    jbLogPos = (jbLogPos + 1) % JB_LOG_LINES;
    if (jbLogCount < JB_LOG_LINES) jbLogCount++;
    Serial.printf("[LOG] %s\n", jbLog[(jbLogPos + JB_LOG_LINES - 1) % JB_LOG_LINES]);
}

static void jbSetStage(int s, const char *why) {
    if (s <= jb.stage || s >= JB_STAGE_COUNT) return;
    jb.stage = (uint8_t)s;
    jb.stageMs = millis();
    jbLogAdd("STG%d %s", s, why);
    Serial.printf("[JB] stage=%d %s\n", s, why);
}

static void jbSetExploit(const char *name) {
    if (strcmp(jb.exploit, name) == 0) return;
    snprintf(jb.exploit, sizeof(jb.exploit), "%s", name);
    jbLogAdd("EXP %s", name);
    Serial.printf("[JB] exploit=%s\n", name);
}

// Sony Interactive Entertainment OUIs -> PS5 vs generic client
static bool macIsSony(const uint8_t *mac) {
    static const uint8_t OUI[][3] = {
        {0x3C, 0xBD, 0xD8}, {0xF0, 0xBF, 0x97}, {0x78, 0xC8, 0x81},
        {0x28, 0x3F, 0x69}, {0x00, 0x13, 0x15},
    };
    for (auto &o : OUI)
        if (mac[0] == o[0] && mac[1] == o[1] && mac[2] == o[2]) return true;
    return false;
}

static void pollStations() {
    uint8_t n = WiFi.softAPgetStationNum();
    if (n > jb.stations) {
        struct station_info *info = wifi_softap_get_station_info();
        if (info) {
            snprintf(jb.ps5Mac, sizeof(jb.ps5Mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                     info->bssid[0], info->bssid[1], info->bssid[2],
                     info->bssid[3], info->bssid[4], info->bssid[5]);
            jb.isSony = macIsSony(info->bssid);
            wifi_softap_free_station_info();
        }
        jb.sessionUp = true;
        jbLogAdd("%s JOIN %s", jb.isSony ? "PS5" : "STA", jb.ps5Mac);
        Serial.printf("[JB] station join n=%u mac=%s sony=%d\n", n, jb.ps5Mac, jb.isSony);
        if (jb.stage == JB_WAIT) jbSetStage(JB_ONLINE, jb.isSony ? "ps5 online" : "client on");
    } else if (n < jb.stations && n == 0) {
        jb.leftAt = millis();
        jbLogAdd("STA LEFT");
        Serial.println("[JB] station left");
    }
    jb.stations = n;
    // session end: gone >2s -> reset inference (PS5 rebooted / walked away)
    if (jb.stations == 0 && jb.sessionUp && jb.leftAt &&
        millis() - jb.leftAt > 2000 && jb.stage != JB_WAIT) {
        jb.sessionUp = false;
        jb.stage = JB_WAIT;
        jb.fw[0] = 0;
        jb.exploit[0] = 0;
        jb.isSony = false;
        jb.ps5Mac[0] = 0;
        jbLogAdd("SESSION RST");
        Serial.println("[JB] session reset");
    }
}

// classify every served path -> stage / fw / exploit / log
static void jbObserve(const String &raw) {
    String p = normalizePath(raw);
    jb.reqCount++;
    jb.lastReqMs = millis();
    snprintf(jb.lastPath, sizeof(jb.lastPath), "%s", p.c_str());

    if (jb.stage == JB_WAIT || jb.stage == JB_ONLINE)
        jbSetStage(JB_BROWSER, "http seen");

    String sp = p;
    if (sp.startsWith("/app/0.5.2")) sp = sp.substring(10);
    if (!sp.length()) sp = "/";
    if (sp.endsWith(".gz")) sp.remove(sp.length() - 3);
    char tail[17];
    snprintf(tail, sizeof(tail), "%s", sp.c_str());
    jbLogAdd("GET %s", tail);

    if (p == "/" || p == "/index.html" || p == "/index.html.gz")
        jbSetStage(JB_INSTALLER, "installer");
    if (p.startsWith("/document/"))
        jbSetStage(JB_INSTALLER, "ps5 redirect");

    if (p.indexOf("/umtx2/") >= 0) jbSetExploit("umtx2");
    else if (p.indexOf("/relapse/") >= 0) jbSetExploit("relapse");
    else if (p.indexOf("/slopkit/") >= 0) jbSetExploit("slopkit");

    int oi = p.indexOf("/offsets/");
    if (oi >= 0 && p.indexOf(".js") >= 0) {
        String v = p.substring(oi + 9);
        int js = v.indexOf(".js");
        if (js > 0) {
            v = v.substring(0, js);
            snprintf(jb.fw, sizeof(jb.fw), "%s", v.c_str());
            jbLogAdd("FW %s", jb.fw);
            Serial.printf("[JB] firmware=%s\n", jb.fw);
            jbSetStage(JB_FW, "fw seen");
        }
    }

    bool exploitSub = sp.startsWith("/umtx2/") || sp.startsWith("/relapse/") || sp.startsWith("/slopkit/");

    if (p.startsWith("/app/") || p.endsWith("selected_exploit"))
        jbSetStage(JB_PAYLOAD_UI, "payload ui");

    if (exploitSub && (sp.endsWith("/index.html") || sp.endsWith("/main.js") ||
                       sp.endsWith("/psfree.js") || sp.endsWith("/umtx2.js") ||
                       sp.endsWith("/relapse.js") || sp.endsWith("/slopkit.js")))
        jbSetStage(JB_EXPLOIT, "exploit run");

    if (exploitSub && (sp.indexOf("rop") >= 0 || sp.indexOf("kexp") >= 0 ||
                       sp.indexOf("syscalls") >= 0 || sp.indexOf("firmware") >= 0 ||
                       sp.indexOf("chain.js") >= 0 || sp.indexOf("mem.js") >= 0 ||
                       sp.indexOf("memtools") >= 0 || sp.indexOf("exploit.js") >= 0))
        jbSetStage(JB_KERNEL, "kernel/rop");
}

// ============================================================
// OLED DISPLAY: autodetect + 3 rotating pages
// ============================================================
static OledDriver *oled = nullptr;
static uint8_t oledAddr = 0;
static int oledSda = -1, oledScl = -1;

#define UI_PAGE_MS 6000
static uint8_t uiPage = 0;
static uint32_t uiLastFlip = 0;
static String uiLine[6];  // cached render lines (avoid per-frame heap churn)

static bool displayDetect() {
    // ideaspark VR2.1 manual: SDA = GPIO12 (D6), SCL = GPIO14 (D5)
    const struct { int sda, scl; } pins[] = {{12, 14}, {14, 12}, {4, 5}, {5, 4}, {4, 15}, {14, 13}, {13, 14}, {12, 13}};
    const uint8_t addrs[] = {0x3C, 0x3D};
    for (auto &pp : pins) {
        Wire.begin(pp.sda, pp.scl);
        Wire.setClock(400000);
        for (uint8_t a : addrs) {
            Wire.beginTransmission(a);
            if (Wire.endTransmission() != 0) continue;
            oled = new OledDriver(a, pp.sda, pp.scl, GEOMETRY_128_64);
            if (!oled->init()) {
                Serial.printf("[OLED] init failed @0x%02X\n", a);
                delete oled;
                oled = nullptr;
                continue;
            }
            oled->flipScreenVertically();
            oledAddr = a;
            oledSda = pp.sda;
            oledScl = pp.scl;
            Serial.printf("[OLED] %s found @0x%02X SDA=%d SCL=%d\n",
#if OLED_DRIVER_SH1106
                          "SH1106",
#else
                          "SSD1306",
#endif
                          a, pp.sda, pp.scl);
            return true;
        }
    }
    Serial.println("[OLED] not found");
    return false;
}

static void uiSet(int i, const char *fmt, ...) {
    char b[32];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(b, sizeof(b), fmt, ap);
    va_end(ap);
    if (uiLine[i] != b) uiLine[i] = b;
}

static void uiMsg3(const char *l1, const char *l2, const char *l3) {
    if (!oled) return;
    oled->clear();
    oled->setTextAlignment(TEXT_ALIGN_CENTER);
    oled->setFont(ArialMT_Plain_16);
    if (l1) oled->drawString(64, 0, l1);
    oled->setTextAlignment(TEXT_ALIGN_LEFT);
    oled->setFont(ArialMT_Plain_10);
    if (l2) oled->drawString(0, 30, l2);
    if (l3) oled->drawString(0, 46, l3);
    oled->display();
}

static const char *uiBigStatus() {
    static char b[20];
    if ((jb.stage >= JB_EXPLOIT || jb.stage == JB_FW) && jb.lastReqMs &&
        millis() - jb.lastReqMs > 15000) {
        snprintf(b, sizeof(b), "CHECK PS5!");
        return b;
    }
    if (jb.stage == JB_FW && jb.fw[0]) {
        snprintf(b, sizeof(b), "FW %s", jb.fw);
        return b;
    }
    if (jb.stage == JB_ONLINE && !jb.isSony)
        return "CLIENT ON";
    return JB_STAGE_NAME[jb.stage];
}

static void uiDashboard() {
    char b[32], up[10];
    fmtUp(up, sizeof(up));
    oled->setTextAlignment(TEXT_ALIGN_LEFT);
    oled->setFont(ArialMT_Plain_10);
    oled->drawString(0, 0, F("PS5 JB LOADER"));
    oled->setTextAlignment(TEXT_ALIGN_RIGHT);
    oled->drawString(127, 0, up);

    oled->setTextAlignment(TEXT_ALIGN_LEFT);
    uiSet(0, "AP %s C:%u", AP_SSID, jb.stations);
    oled->drawString(0, 13, uiLine[0]);

    oled->setFont(ArialMT_Plain_16);
    oled->setTextAlignment(TEXT_ALIGN_CENTER);
    oled->drawString(64, 25, uiBigStatus());

    oled->setFont(ArialMT_Plain_10);
    oled->setTextAlignment(TEXT_ALIGN_LEFT);
    if (jb.fw[0] && jb.exploit[0])
        uiSet(1, "FW %s %s  S%d/7", jb.fw, jb.exploit, jb.stage);
    else if (jb.fw[0])
        uiSet(1, "FW %s  S%d/7", jb.fw, jb.stage);
    else if (jb.exploit[0])
        uiSet(1, "EXP %s  S%d/7", jb.exploit, jb.stage);
    else
        uiSet(1, "REQ %u  ERR %u  S%d/7", (unsigned)jb.reqCount, (unsigned)jb.errCount, jb.stage);
    oled->drawString(0, 46, uiLine[1]);

    oled->drawProgressBar(0, 57, 127, 6, (uint8_t)(jb.stage * 100 / (JB_STAGE_COUNT - 1)));
}

static void uiLogPage() {
    char b[32];
    oled->setTextAlignment(TEXT_ALIGN_LEFT);
    oled->setFont(ArialMT_Plain_10);
    oled->drawString(0, 0, F("LIVE LOG"));
    oled->setTextAlignment(TEXT_ALIGN_RIGHT);
    snprintf(b, sizeof(b), "R:%u E:%u", (unsigned)jb.reqCount, (unsigned)jb.errCount);
    oled->drawString(127, 0, b);

    oled->setTextAlignment(TEXT_ALIGN_LEFT);
    int n = jbLogCount < 4 ? jbLogCount : 4;
    for (int i = 0; i < n; i++) {
        int idx = (jbLogPos + JB_LOG_LINES - n + i) % JB_LOG_LINES;
        oled->drawString(0, 14 + i * 12, String(jbLog[idx]));
    }
}

static void uiSystemPage() {
    char up[10], b[32];
    fmtUp(up, sizeof(up));
    oled->setTextAlignment(TEXT_ALIGN_LEFT);
    oled->setFont(ArialMT_Plain_10);
    oled->drawString(0, 0, F("SYSTEM"));
    oled->setTextAlignment(TEXT_ALIGN_RIGHT);
    snprintf(b, sizeof(b), "%s O%02X", FW_VER, oledAddr);
    oled->drawString(127, 0, b);

    oled->setTextAlignment(TEXT_ALIGN_LEFT);
    uiSet(0, "CHIP %08X", ESP.getChipId());
    oled->drawString(0, 13, uiLine[0]);
    uiSet(1, "MAC %s", WiFi.softAPmacAddress().c_str());
    oled->drawString(0, 25, uiLine[1]);
    uiSet(2, "HEAP %uK UP %s", ESP.getFreeHeap() / 1024, up);
    oled->drawString(0, 37, uiLine[2]);
    uiSet(3, "CLIENT %s", jb.ps5Mac[0] ? jb.ps5Mac : "none");
    oled->drawString(0, 49, uiLine[3]);
}

static void uiTick() {
    if (!oled) return;
    uint32_t now = millis();
    if (now - uiLastFlip > UI_PAGE_MS) {
        uiPage = (uiPage + 1) % 3;
        uiLastFlip = now;
    }
    oled->clear();
    switch (uiPage) {
        case 0: uiDashboard(); break;
        case 1: uiLogPage(); break;
        default: uiSystemPage(); break;
    }
    oled->display();
}

// ============================================================
// HTTP helpers (original behavior + JB hooks)
// ============================================================
static void logHeap(const char *where) {
    Serial.printf("[HEAP] %s: free=%u\n", where, ESP.getFreeHeap());
}

static String normalizePath(const String &uri) {
    String path = uri;
    int q = path.indexOf('?');
    if (q >= 0) path = path.substring(0, q);
    if (!path.length()) path = "/";
    return path;
}

static String contentType(const String &path) {
    if (path.endsWith(".html") || path.endsWith(".htm")) return "text/html; charset=utf-8";
    if (path.endsWith(".css")) return "text/css";
    if (path.endsWith(".js") || path.endsWith(".mjs")) return "application/javascript";
    if (path.endsWith(".json")) return "application/json";
    if (path.endsWith(".png")) return "image/png";
    if (path.endsWith(".jpg") || path.endsWith(".jpeg")) return "image/jpeg";
    if (path.endsWith(".gif")) return "image/gif";
    if (path.endsWith(".svg")) return "image/svg+xml";
    if (path.endsWith(".ico")) return "image/x-icon";
    if (path.endsWith(".appcache") || path.endsWith(".manifest") || path.endsWith(".cache")) return "text/cache-manifest";
    if (path.endsWith(".woff")) return "font/woff";
    if (path.endsWith(".woff2")) return "font/woff2";
    return "application/octet-stream";
}

template <typename Server>
static void noCache(Server &server) {
    server.sendHeader("Cache-Control", NO_CACHE_VALUE);
    server.sendHeader("Pragma", "no-cache");
    server.sendHeader("Expires", "0");
}

template <typename Server>
static void logRequest(Server &server) {
    Serial.printf("[HTTP] %s %s", server.method() == HTTP_GET ? "GET" :
                  server.method() == HTTP_POST ? "POST" : "OTHER", server.uri().c_str());
    for (int i = 0; i < server.args(); i++)
        Serial.printf("%c%s=%s", i ? '&' : '?', server.argName(i).c_str(), server.arg(i).c_str());
    Serial.println();
}

template <typename Server>
static void fileHandler(Server &server) {
    String path = normalizePath(server.uri());
    jbObserve(path);

    if (path.startsWith("/networktest/")) {
        noCache(server);
        server.send(200, "text/plain", "OK");
        return;
    }

    if (path.startsWith(PAYLOAD_MIRROR_PREFIX)) {
        String original = path;
        path = String(PAYLOAD_LOCAL_PREFIX) + path.substring(strlen(PAYLOAD_MIRROR_PREFIX));
        Serial.printf("[HTTP] Rewrite: %s -> %s\n", original.c_str(), path.c_str());
    }
    if (path.endsWith("/")) path += "index.html";
    else if (!LittleFS.exists(path) && LittleFS.exists(path + "/index.html")) path += "/index.html";

    bool gzip = false;
    File file = LittleFS.open(path + ".gz", "r");
    if (file && !file.isDirectory()) {
        gzip = true;
    } else {
        if (file) file.close();
        file = LittleFS.open(path, "r");
    }
    if (!file || file.isDirectory()) {
        if (file) file.close();
        if (path.startsWith("/document/") && (path.indexOf("/ps5") >= 0 || path.indexOf("/ps4") >= 0)) {
            server.sendHeader("Location", PORTAL_REDIRECT_URL, true);
            server.send(302, "text/plain", "");
        } else {
            jb.errCount++;
            jbLogAdd("404 %s", path.c_str());
            server.send(404, "text/plain", "404 Not Found");
        }
        return;
    }

    // smart: learn chosen exploit from the selected_exploit marker file
    if (path.endsWith("selected_exploit")) {
        char sel[16] = {0};
        size_t n = file.readBytes(sel, sizeof(sel) - 1);
        sel[n] = 0;
        for (size_t i = 0; i < n; i++) if (sel[i] < 32 || sel[i] > 126) sel[i] = 0;
        if (strlen(sel)) {
            jbSetExploit(sel);
            file.seek(0, SeekSet);
        }
    }

    String type = contentType(path);
    if (gzip && type == "application/octet-stream")
        server.sendHeader("Content-Encoding", "gzip");

    server.streamFile(file, type);
    file.close();
}

template <typename Server>
static void setupRoutes(Server &server) {
    server.on("/generate_204", HTTP_GET, [&server]() { jbObserve(server.uri()); noCache(server); server.send(204); });
    server.on("/gen_204", HTTP_GET, [&server]() { jbObserve(server.uri()); noCache(server); server.send(204); });
    server.on("/hotspot-detect.html", HTTP_GET, [&server]() { jbObserve(server.uri()); noCache(server); server.send(200, "text/html", "Success"); });
    server.on("/connecttest.txt", HTTP_GET, [&server]() { jbObserve(server.uri()); noCache(server); server.send(200, "text/plain", "Microsoft Connect Test"); });
    server.on("/ncsi.txt", HTTP_GET, [&server]() { jbObserve(server.uri()); noCache(server); server.send(200, "text/plain", "Microsoft NCSI"); });
    server.on("/redirect", HTTP_GET, [&server]() { jbObserve(server.uri()); noCache(server); server.send(200, "text/plain", "Success"); });
    server.on("/netstart/icst", HTTP_GET, [&server]() { jbObserve(server.uri()); noCache(server); server.send(200, "text/plain", "Success"); });
    server.onNotFound([&server]() { fileHandler(server); });
    server.begin();
}

// ============================================================
void setup() {
    Serial.begin(115200);
    Serial.setDebugOutput(false);
    delay(500);
    jbBootMs = millis();

    Serial.println("\nBOOT ESP8266");
    Serial.printf("Core: %s, SDK: %s\n", ESP.getCoreVersion().c_str(), ESP.getSdkVersion());
    Serial.printf("Reset: %s\n", ESP.getResetReason().c_str());
    Serial.printf("FW: %s smart-UI\n", FW_VER);

    bool hasDisplay = displayDetect();
    if (hasDisplay) {
        char idb[16];
        snprintf(idb, sizeof(idb), "%08X", ESP.getChipId());
        uiMsg3("PS5 JB", FW_VER, idb);
        delay(900);
    }

    if (!LittleFS.begin()) {
        Serial.println("LittleFS: FAILED");
        if (hasDisplay) {
            uiMsg3("! FS FAIL", "no payload files", "check image");
            delay(3000);
        }
    } else {
        FSInfo info;
        LittleFS.info(info);
        Serial.printf("LittleFS: OK, total=%u, used=%u bytes\n", info.totalBytes, info.usedBytes);
        if (hasDisplay) {
            uiMsg3("FS OK", "payload files mounted", NULL);
            delay(700);
        }
    }

    WiFi.persistent(false);
    WiFi.mode(WIFI_OFF);
    delay(200);
    WiFi.mode(WIFI_AP);

    Serial.printf("softAPConfig: %s\n", WiFi.softAPConfig(AP_IP, AP_GATEWAY, AP_SUBNET) ? "OK" : "FAILED");
    bool ap = WiFi.softAP(AP_SSID, AP_PASSWORD);
    Serial.printf("softAP: %s\n", ap ? "OK" : "FAILED");
    if (!ap) {
        if (hasDisplay) {
            uiMsg3("! AP FAIL", "softAP() failed", "reboot me");
            while (true) delay(1000);
        }
        while (true) delay(1000);
    }

    Serial.printf("AP IP: %s\n", WiFi.softAPIP().toString().c_str());
    Serial.printf("SSID: %s\n", WiFi.softAPSSID().c_str());
    Serial.printf("Channel: %d\n", WiFi.channel());
    Serial.printf("MAC: %s\n", WiFi.softAPmacAddress().c_str());
    Serial.printf("DNS: %s\n", dnsServer.start(53, "*", AP_IP) ? "OK" : "FAILED");

    Serial.println("Starting HTTP");
    setupRoutes(webServer);
    logHeap("HTTP ready");

    if (hasDisplay) {
        uiMsg3("AP READY", AP_SSID, "connect PS5 now");
        delay(900);
        uiPage = 0;
        uiLastFlip = millis();
    }
    Serial.println("READY");
}

static uint32_t lastPoll = 0;
static uint32_t lastUi = 0;

void loop() {
    dnsServer.processNextRequest();
    webServer.handleClient();

    uint32_t now = millis();
    if (now - lastPoll >= 500) {
        lastPoll = now;
        pollStations();
    }
    if (oled && now - lastUi >= 250) {
        lastUi = now;
        uiTick();
    }
    delay(2);
}
