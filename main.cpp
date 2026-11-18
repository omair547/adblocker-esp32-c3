#include <WiFi.h>
#include <WiFiUdp.h>
#include <LittleFS.h>
#include <unordered_set>
#include <string>

const char* WIFI_SSID = "YOUR_SSID";
const char* WIFI_PASS = "YOUR_PASSWORD";
const IPAddress UPSTREAM(1, 1, 1, 1);

WiFiUDP dnsServer, upstreamSock;
std::unordered_set<std::string> blocked;
uint8_t buf[512], resp[1500];

void loadBlocklist() {
  File f = LittleFS.open("/blocklist.txt", "r");
  if (!f) { Serial.println("No blocklist"); return; }
  while (f.available()) {
    String l = f.readStringUntil('\n');
    l.trim(); l.toLowerCase();
    if (l.length() && l[0] != '#') blocked.insert(l.c_str());
  }
  Serial.printf("Loaded %lu domains, free heap %lu\n",
                (unsigned long)blocked.size(), (unsigned long)ESP.getFreeHeap());
}

// Parse QNAME starting at byte 12. Returns end-of-question offset, or -1.
int parseQuery(int len, std::string &name, uint16_t &qtype) {
  int i = 12;
  while (i < len && buf[i] != 0) {
    int l = buf[i++];
    if (l > 63 || i + l > len) return -1;
    if (!name.empty()) name += '.';
    for (int k = 0; k < l; k++) name += tolower(buf[i + k]);
    i += l;
  }
  if (i + 5 > len) return -1;
  qtype = (buf[i + 1] << 8) | buf[i + 2];
  return i + 5;
}

bool isBlocked(const std::string &name) {
  size_t pos = 0;
  while (true) {
    if (blocked.count(name.substr(pos))) return true;
    pos = name.find('.', pos);
    if (pos == std::string::npos) return false;
    pos++;
  }
}

int buildBlockedReply(int qEnd, uint16_t qtype) {
  memcpy(resp, buf, qEnd);
  resp[2] = 0x81; resp[3] = 0x80;               // response, RD, RA, no error
  resp[6] = 0; resp[7] = (qtype == 1) ? 1 : 0;  // ANCOUNT (A records only)
  resp[8] = resp[9] = resp[10] = resp[11] = 0;
  int n = qEnd;
  if (qtype == 1) {
    const uint8_t ans[] = {0xC0,0x0C, 0,1, 0,1, 0,0,0,60, 0,4, 0,0,0,0};
    memcpy(resp + n, ans, sizeof(ans));
    n += sizeof(ans);
  }
  return n;
}

void setup() {
  Serial.begin(115200);
  Serial.setTxTimeoutMs(0);   // don't stall if no PC is attached
  delay(1500);

  LittleFS.begin(true);
  loadBlocklist();

  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);                       // lower DNS latency
  WiFi.setTxPower(WIFI_POWER_8_5dBm);         // helps many Super Mini boards connect
  WiFi.setAutoReconnect(true);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  while (WiFi.status() != WL_CONNECTED) { delay(300); Serial.print('.'); }
  Serial.printf("\nDNS server IP: %s\n", WiFi.localIP().toString().c_str());

  dnsServer.begin(53);
  upstreamSock.begin(5353);
}

void loop() {
  if (WiFi.status() != WL_CONNECTED) {
    WiFi.reconnect();
    delay(1000);
    return;
  }

  int len = dnsServer.parsePacket();
  if (len <= 12 || len > 512) return;
  IPAddress clientIP = dnsServer.remoteIP();
  uint16_t clientPort = dnsServer.remotePort();
  dnsServer.read(buf, len);

  std::string name; uint16_t qtype;
  int qEnd = parseQuery(len, name, qtype);
  if (qEnd < 0) return;

  if (isBlocked(name)) {
    Serial.printf("BLOCK %s\n", name.c_str());
    int n = buildBlockedReply(qEnd, qtype);
    dnsServer.beginPacket(clientIP, clientPort);
    dnsServer.write(resp, n);
    dnsServer.endPacket();
    return;
  }

  // Forward to upstream resolver
  upstreamSock.beginPacket(UPSTREAM, 53);
  upstreamSock.write(buf, len);
  upstreamSock.endPacket();

  uint32_t start = millis();
  while (millis() - start < 2000) {
    int rl = upstreamSock.parsePacket();
    if (rl > 0 && rl <= (int)sizeof(resp)) {
      upstreamSock.read(resp, rl);
      if (resp[0] == buf[0] && resp[1] == buf[1]) {   // match query ID
        dnsServer.beginPacket(clientIP, clientPort);
        dnsServer.write(resp, rl);
        dnsServer.endPacket();
        return;
      }
    }
    delay(1);
  }
}