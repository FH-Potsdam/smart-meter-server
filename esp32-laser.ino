#include <AESLib.h>
#include <ESPmDNS.h>
#include <WiFi.h>
#include <SPI.h>
#include "RTClib.h"
#include "FS.h"
#include "SD.h"
#include "SPI.h"
#include <HTTPClient.h>
#include "esp_wifi.h"
#include <ArduinoJson.h>

float threshold = 2.0;
float price = 10.0/60.0; // price per minute
float exPrice = 0.5; // external price per minute

RTC_DS3231 rtc;
AESLib aesLib;

char cleartext[256];
char ciphertext[512];


byte aes_key[] =       { 0x64, 0x66, 0x37, 0x31, 0x39, 0x21, 0x53, 0x67, 0x35, 0x50, 0x5B, 0x5F, 0x34, 0x5D, 0x77, 0x34 };

byte aes_iv[N_BLOCK] = { 0x65, 0x6A, 0x77, 0x64, 0x2D, 0x66, 0x37, 0x38, 0x67, 0x5A, 0x68, 0x65, 0x52, 0x2B, 0x6E, 0x33 };

byte enc_iv[N_BLOCK] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
byte dec_iv[N_BLOCK] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

const char* ssid = "LASER";

// Set your Static IP address
IPAddress local_IP(192, 168, 1, 5);
// Set your Gateway IP address
IPAddress gateway(192, 168, 1, 1);

IPAddress subnet(255, 255, 255, 0);

const char* PARAM_SECRET = "secret";
const char* PARAM_TIME = "time";

String serverName = "/cm?cmnd=Status+8";
unsigned long lastTime = 0;
unsigned long timerDelay = 10000;

// secret for special features
String secret = "SET_SECRET_PASSWORD_HERE";

WiFiServer server(80);
String header;

void setup() {
  Serial.begin(115200);

  if (!rtc.begin()) {
    Serial.println("Couldn't find RTC");
  }

  if (!SD.begin(5)) {
    Serial.println("Card Mount Failed");
    return;
  }
  uint8_t cardType = SD.cardType();

  if (cardType == CARD_NONE) {
    Serial.println("No SD card attached");
    return;
  } else {
    Serial.println("SD Card connected");
  }

  Serial.println("Setting AP (Access Point)…");
  WiFi.mode(WIFI_AP);
  WiFi.softAP(ssid);
  delay(2000);

  WiFi.softAPConfig(local_IP, gateway, subnet);
  delay(2000);

  IPAddress IP = WiFi.softAPIP();
  Serial.print("AP IP address: ");
  Serial.println(IP);

  // laser.local works everywhere besides android?!!
  while (!MDNS.begin("laser")) {
    Serial.println("Starting mDNS...");
    delay(1000);
  }

  Serial.println("MDNS started");

  server.begin();

  Serial.println("Server started");

  aesLib.gen_iv(aes_iv);
  aesLib.set_paddingmode(paddingMode::CMS);

  Serial.println("Crypto setup");

  Serial.println("setup complete");
}

String encrypt_impl(char * msg, byte iv[]) {
  int msgLen = strlen(msg);
  char encrypted[2 * msgLen] = {0};
  aesLib.encrypt64((const byte*)msg, msgLen, encrypted, aes_key, sizeof(aes_key), iv);
  return String(encrypted);
}

String decrypt_impl(char * msg, byte iv[]) {
  int msgLen = strlen(msg);
  char decrypted[msgLen] = {0}; // half may be enough
  aesLib.decrypt64(msg, msgLen, (byte*)decrypted, aes_key, sizeof(aes_key), iv);
  return String(decrypted);
}

String getParam(String header, String key) {
  key += "=";
  String returnValue = String();
  String firstLine = header.substring(0, header.indexOf(("\r")));
  int urlStart = firstLine.indexOf(" ");
  int urlEnd = firstLine.indexOf(" ", urlStart + 1);
  String url = firstLine.substring(urlStart, urlEnd);
  if (url.indexOf("?") >= 0) {
    String params = url.substring(url.indexOf("?") + 1);
    if (params.indexOf(key) >= 0) {
      if (params.indexOf("&", params.indexOf(key) + 1) >= 0) {
        returnValue = params.substring(params.indexOf(key) + key.length(), params.indexOf("&", params.indexOf(key) + 1));
      } else {
        returnValue = params.substring(params.indexOf(key) + key.length());
      }
    }
  }
  returnValue.trim();
  returnValue.replace("~", "-");
  return returnValue;
}

String selector(String name, int min, int max, int selected) {
  String r = "<select name='";
  r += name;
  r += "'>";
  for (int i = min; i <= max; i++){
    r += "<option value='";
    r += i;
    r +="'";
    if (selected == i) {
      r+= " selected";
    }
    r += ">";
    if (i < 10) {
      r += "0";
    }
    r += i;
    r += "</option>";
  }
  r += "</select>";
  return r;
}

#define MAX_UID 8 /* Change to whatever length you need */

String generateUID(){
  /* Change to allowable characters */
  const char possible[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  String uid;
  for(int p = 0, i = 0; i < MAX_UID; i++){
    int r = random(0, strlen(possible));
    uid += possible[r];
  }
  return uid;
}

unsigned char h2int(char c) {
    if (c >= '0' && c <='9'){
        return((unsigned char)c - '0');
    }
    if (c >= 'a' && c <='f'){
        return((unsigned char)c - 'a' + 10);
    }
    if (c >= 'A' && c <='F'){
        return((unsigned char)c - 'A' + 10);
    }
    return(0);
}

String urldecode(String str){
  String encodedString="";
  char c;
  char code0;
  char code1;
  for (int i =0; i < str.length(); i++){
    c=str.charAt(i);
    if (c == '+'){
      encodedString+=' ';  
    } else if (c == '%') {
      i++;
      code0=str.charAt(i);
      i++;
      code1=str.charAt(i);
      c = (h2int(code0) << 4) | h2int(code1);
      encodedString+=c;
    } else {
      encodedString+=c;  
    }
    yield();
  }
  return encodedString;
}

// smart power meter's mac address in uint8_t
uint8_t power_mac[] = { 140, 206, 78, 42, 43, 80 };

void loop() {
  if ((millis() - lastTime) > timerDelay) {
    lastTime = millis();

    DateTime now = rtc.now();
    char seq[6][16];
    itoa(now.year(),    seq[0], 10);
    itoa(now.month(),   seq[1], 10);
    itoa(now.day(),     seq[2], 10);       
    itoa(now.hour(),    seq[3], 10);
    itoa(now.minute(),  seq[4], 10);
    itoa(now.second(),  seq[5], 10);

    // Setting up the current folder path
    for (int s = 0; s < 3; s++) {
      String path;
      for (int si = 0; si <= s; si++) {
        path += "/";
        path += seq[si];
      }
      File filePath = SD.open(path);
      if(!filePath || !filePath.isDirectory()){
        if(SD.mkdir(path)) {
          // Serial.println("completed");
        } else {
          Serial.println("mkdir failed");
        }
      }
    }

    // Identify the power sensor
    wifi_sta_list_t wifi_sta_list;
    tcpip_adapter_sta_list_t adapter_sta_list;

    memset(&wifi_sta_list, 0, sizeof(wifi_sta_list));
    memset(&adapter_sta_list, 0, sizeof(adapter_sta_list));

    esp_wifi_ap_get_sta_list(&wifi_sta_list);
    tcpip_adapter_get_sta_list(&wifi_sta_list, &adapter_sta_list);

    for (int i = 0; i < adapter_sta_list.num; i++) {

      tcpip_adapter_sta_info_t station = adapter_sta_list.sta[i];

      bool isPower = true;
      for(int m = 0; m < 6; m++){
        if (power_mac[m] != station.mac[m]) {
          isPower = false;
        }
      }
      if (isPower) {
        HTTPClient http;
        String httpPrefix = "http://";
        String serverPath = httpPrefix + ip4addr_ntoa(&(station.ip)) + serverName;
        Serial.println(serverPath);
        http.setAuthorization("SMART_SOCKET_USER", "SMART_SOCKET_PASSWORD"); // alt- setBasicAuth / setAuthorization(base_64_string)
        http.useHTTP10(true);
        http.begin(serverPath);
        int httpResponseCode = http.GET();
        if (httpResponseCode>0) {
          DynamicJsonDocument doc(2048);
          DeserializationError error = deserializeJson(doc, http.getStream());
          if (error) {
            Serial.print(F("deserializeJson() failed: "));
            Serial.println(error.f_str());
          } else {
            // Power, ApparentPower, ReactivePower, Factor, Voltage
            double currentPower = doc["StatusSNS"]["ENERGY"]["Current"];

            String path;
            for (int s = 0; s < 4; s++) {
              path += "/";
              path += seq[s];
            }
            File file = SD.open(path, FILE_APPEND);
            if(!file){
              Serial.println("Failed to open file for appending");
            } else {
              String message;
              message += seq[4];
              message += ",";
              message += seq[5];
              message += ",";
              message += currentPower;
              message += "\n";
              file.print(message);
              file.close();
            }
          }
        } else {
          Serial.print("Error code: ");
          Serial.println(httpResponseCode);
        }
        http.end();
      }
    }
  }

  WiFiClient client = server.available();  // Listen for incoming clients

  if (client) {                     // If a new client connects,
    String currentLine = "";        // make a String to hold incoming data from the client
    while (client.connected()) {    // loop while the client's connected
      if (client.available()) {     // if there's bytes to read from the client,
        char c = client.read();     // read a byte, then
        header += c;
        if (c == '\n') {  // if the byte is a newline character
          // if the current line is blank, you got two newline characters in a row.
          // that's the end of the client HTTP request, so send a response:
          if (currentLine.length() == 0) {
            // HTTP headers always start with a response code (e.g. HTTP/1.1 200 OK)
            // and a content-type so the client knows what's coming, then a blank line:
            client.println("HTTP/1.1 200 OK");
            client.println("Content-type:text/html");
            client.println("Connection: close");
            client.println();

            client.println("<!DOCTYPE html><html>");
            client.println("<head><meta name='viewport' content='width=device-width, initial-scale=1'><title>LASER</title><meta charset='utf-8'>");
            client.println("<style>*{margin:0;padding:0;border:none;box-sizing:border-box;color:white;font-family:Helvetica, Arial, sans-serif;}th{font-weight:bold;text-align:left;border-bottom:2px solid white;border-right:1px solid white;}td{border-bottom:1px solid bottom;border-right:1px solid white;}html{background-image:linear-gradient(#14a873,#358ccb);min-height:100vh;width:100%;padding:0 10px 50px 10px;}header{display:flex;flex-direction:row;margin-bottom:30px;}svg{margin:-20px 20px 0 0;width:30px;height:auto;}h1{padding-top:8px;}svg line,svg path{fill:none;stroke-linecap:round;stroke-width:3px;stroke:white;}select,input{color:#358ccb;background:white;border:1px solid white;border-radius:4px;padding:3px;}input{max-width:100%;width:400px;}option{color:#358ccb;}option[selected]{color:black;font-weight:bold;}form{display:flex;flex-direction:column;}p{max-width:400px;}p.big{font-size:24px;font-weight:bold;}label{display:block;margin:16px 0 4px 0;font-weight:bold;}label.hl{text-decoration:underline;}footer{padding-top:50px;}</style>");
            client.println("</head><body>");
            client.println("<header><svg width='46' height='115' viewBox='0 0 46 115'><path d='M10 1.5H36C40.6944 1.5 44.5 5.30558 44.5 10V49.7055C44.5 51.5243 43.9166 53.2951 42.8355 54.7578L30.7917 71.0523C29.189 73.2207 26.6526 74.5 23.9562 74.5H22.0438C19.3474 74.5 16.811 73.2207 15.2083 71.0523L3.1645 54.7578C2.08341 53.2951 1.5 51.5243 1.5 49.7055V10C1.5 5.30558 5.30558 1.5 10 1.5Z'/><line x1='7' y1='59.5' x2='39' y2='59.5'/><line x1='23.5' y1='75.5' x2='23.5' y2='103.5'/><line x1='28.708' y1='101.248' x2='37.0003' y2='97.292'/><line x1='9.70804' y1='112.248' x2='18.0003' y2='108.292'/><line x1='28.9996' y1='108.292' x2='37.2921' y2='112.247'/><line x1='9.99964' y1='97.2919' x2='18.2921' y2='101.247'/></svg><h1>LASER</h1></header>");
            client.println("<main>");

            if (header.indexOf("GET /gettime") >= 0) {
              DateTime now = rtc.now();
              String response =
                String(now.year()) + "-" + String(now.month()) + "-" + String(now.day()) + " " + String(now.hour()) + ":" + String(now.minute()) + " " + String(now.second());
              client.println(response);
            } else if (header.indexOf("GET /settime") >= 0) {
              client.println("SETTIME");
              if (getParam(header, "year").length() == 4) {
                rtc.adjust(DateTime(
                  getParam(header, "year").toInt(),
                  getParam(header, "month").toInt(),
                  getParam(header, "day").toInt(),
                  getParam(header, "hour").toInt(),
                  getParam(header, "minute").toInt(),
                  getParam(header, "second").toInt()
                ));
                client.println("TIME SET");
              } else {
                client.println("<script>const d = new Date(); window.location.href='/settime?year='+d.getFullYear()+'&month='+(d.getMonth()+1)+'&day='+d.getDate()+'&hour='+d.getHours()+'&minute='+d.getMinutes()+'&second='+d.getSeconds();</script>");
              }
            } else if (header.indexOf("GET /getusage") >= 0) {
              String uSecret = getParam(header, "password");
              if (uSecret == secret) {
                client.println("<table><thead><tr><th>Name</th><th>Matr.</th><th>EMail</th><th>Ref.</th><th>Zeit</th><th>Kosten</th><th>Datum</th><th>Start</th><th>Ende</th><th>IsSeminar</th><th>Prof.</th><th>Seminar</th><th>IsFB4</th></tr></thead><tbody>");
                File file = SD.open("/usage", FILE_READ);
                if(!file){
                  Serial.println("Failed to open file for reading");
                } else {
                  while(file.available()){
                    client.println("<tr>");
                    String line = file.readStringUntil('\n');

                    int cryptLen = line.indexOf("$$$");
                    String crypt = line.substring(0, cryptLen);
                    int decryptLen = line.substring(cryptLen + 3).toInt();

                    sprintf(ciphertext, "%s", crypt.c_str());
                    String decrypted = decrypt_impl( ciphertext, dec_iv);
                    String dLine = decrypted.substring(0, decryptLen);
                    
                    for (int i = 0; i < 16; i++) {
                      dec_iv[i] = 0;
                    }

                    int splitIdx = -1;
                    while(dLine.indexOf("~", splitIdx + 1) >= 0) {
                      int newIdx = dLine.indexOf("~", splitIdx + 1);
                      client.println("<td>");
                      client.println(urldecode(dLine.substring(splitIdx + 1, newIdx)));
                      client.println("</td>");
                      splitIdx = newIdx;                    
                    }
                    client.println("<td>");
                    client.println(dLine.substring(splitIdx + 1));
                    client.println("</td>");
                                      
                    client.println("</tr>");
                  }
                  file.close();
                }
                client.println("</tbody></table>");
              } else {
                client.println("<form action='/getusage' method='get'><input type='password' name='password' /><input style='margin-top:10px;' type='submit' value='einloggen&nbsp;&raquo;'/></form>");
              }
            } else if (header.indexOf("GET /getpower") >= 0) {
              int sum = 0;
              String year = getParam(header, "year");
              String month = getParam(header, "month");
              String day = getParam(header, "day");
              String sHour = getParam(header, "shour");
              String sMinute = getParam(header, "sminute");
              String eHour = getParam(header, "ehour");
              String eMinute = getParam(header, "eminute");

              String fName = getParam(header, "name");
              String fMatr = getParam(header, "matr");
              String fEmail = getParam(header, "email");
              String fIsseminar = getParam(header, "seminar");
              String fIsfb = getParam(header, "fb");
              String fLecturer = getParam(header, "lecturer");
              String fSeminar = getParam(header, "title");

              for (int h = sHour.toInt(); h <= eHour.toInt(); h++) {
                String path;
                path += "/";
                path += year;
                path += "/";
                path += month;
                path += "/";
                path += day;
                path += "/";
                path += h;
                File file = SD.open(path, FILE_READ);
                if(!file){
                  Serial.println("Failed to open file for reading");
                } else {
                  int lastMinute = -1;
                  while(file.available()){
                    String line = file.readStringUntil('\n');
                    int minuteIndex = line.indexOf(",");
                    int minute = line.substring(0, minuteIndex).toInt();
                    int secondIndex = line.indexOf(",", minuteIndex + 1);
                    int second = line.substring(minuteIndex + 1, secondIndex).toInt();
                    float power = line.substring(secondIndex + 1).toFloat();
                    bool useIt = false;                    
                    if (h > sHour.toInt() && h < eHour.toInt()) {
                      useIt = true;
                    } else if (h == sHour.toInt() && h == eHour.toInt() && sMinute.toInt() <= minute && eMinute.toInt() >= minute) {
                      useIt = true;
                    } else if (h == sHour.toInt() && h != eHour.toInt() && sMinute.toInt() <= minute) {
                      useIt = true;
                    } else if (h == eHour.toInt() && h != sHour.toInt() && eMinute.toInt() >= minute) {
                      useIt = true;
                    }

                    if (useIt && power > threshold && minute > lastMinute) {
                      lastMinute = minute;
                      sum++;
                    }
                  }
                  file.close();
                }
              }

              client.println("<label>Nutzungszeitraum:</label>");
              String workTime = "<p>";
              workTime += day;
              workTime += ".";
              workTime += month;
              workTime += ".";
              workTime += year;
              workTime += "<br />";
              if (sHour.toInt() < 10) {
                workTime += "0";                
              }
              workTime += sHour;
              workTime += ":";
              if (sMinute.toInt() < 10) {
                workTime += "0";                
              }
              workTime += sMinute;
              workTime += " bis ";
              workTime += eHour;
              workTime += ":";
              workTime += eMinute;
              workTime += "</p>";
              client.println(workTime);
              client.println("<label>Laserzeit:</label><p class='big'>");
              client.println(String(sum));
              client.println(" Minuten</p>");
              client.println("<label>Kosten:</label><p class='big'>");
              float tPrice = price;
              if (fIsfb != "4") {
                tPrice = exPrice;
              }
              float cost = sum * tPrice;
              client.println(String(cost, 2));
              client.println(" €</p>");
              client.println("<label>Referenznr.:</label><p class='big'>");
              String uid = generateUID();
              client.println(uid);
              client.println("</p>");
              client.println("<br />");
              
              if (fIsseminar == "ja" && fIsfb == "4") {
                client.println("<p>Die im Rahmen deiner Kursarbeit entstandenen Kosten werden automatisch vom Konto von <b>");
                client.println(fLecturer);
                client.println("</b> abezogen.</p>");
              } else {
                client.println("<p>Bitte überweise die Kosten innerhalb von zwei Wochen am Kassenautomaten auf das Laser-Konto. Schicke danach eine Photo vom Beleg unter Angabe der Referenznr. an laser@fh-potsdam.de</p>");
              }

              File file = SD.open("/usage", FILE_APPEND);
              if(!file){
                Serial.println("Failed to open file for appending");
              } else {
                String readBuffer = fName;
                readBuffer += "~";
                readBuffer += fMatr;
                readBuffer += "~";
                readBuffer += fEmail;
                readBuffer += "~";
                readBuffer += uid;
                readBuffer += "~";
                readBuffer += sum;
                readBuffer += "~";
                readBuffer += String(cost, 2);
                readBuffer += "~";
                readBuffer += day;
                readBuffer += ".";
                readBuffer += month;
                readBuffer += ".";
                readBuffer += year;
                readBuffer += "~";
                readBuffer += sHour;
                readBuffer += ":";
                readBuffer += sMinute;
                readBuffer += "~";
                readBuffer += eHour;
                readBuffer += ":";
                readBuffer += eMinute;
                readBuffer += "~";
                readBuffer += fIsseminar;
                readBuffer += "~";
                readBuffer += fLecturer;
                readBuffer += "~";
                readBuffer += fSeminar;
                readBuffer += "~";
                readBuffer += fIsfb;
                
                sprintf(cleartext, "%s", readBuffer.c_str());
                String encrypted = encrypt_impl(cleartext, enc_iv);
                
                encrypted += "$$$";
                encrypted += String(readBuffer.length());
                encrypted += "\n";

                for (int i = 0; i < 16; i++) {
                  enc_iv[i] = 0;
                }

                file.print(encrypted);
                file.close();
              }

            } else {
              DateTime now = rtc.now();
              // TODO: selected
              client.println("<p>Wenn du deinen Laservorgang abgeschlossen hast, fülle bitte untenstehendes Formular aus. Du erhältst danach einen Auszug der Kosten.</p>");
              client.println("<form method='get' action='/getpower'>");

              client.println("<label>Datum auswählen:</label><div>");
              client.println(selector("day", 1, 31, now.day()));
              client.println(".");
              client.println(selector("month", 1, 12, now.month()));
              client.println(".");
              client.println(selector("year", 2023, now.year(), now.year()));
              client.println("</div>");

              client.println("<label>Startzeit:</label><div>");
              client.println(selector("shour", 0, 23, now.hour()));
              client.println(":");
              client.println(selector("sminute", 0, 59, now.minute()));
              client.println("</div>");

              client.println("<label>Endzeit:</label><div>");
              client.println(selector("ehour", 0, 23, now.hour()));
              client.println(":");
              client.println(selector("eminute", 0, 59, now.minute()));
              client.println("</div>");

              client.println("<label class='hl'>Persönliche Angaben</label><p>Deine Informationen werden verschlüsselt und sind nur für die Betreuer*innen des Lasers zugänglich. Alle Informationen werden nach max. 12 Monaten gelöscht.</p>");
              client.println("<label>Name:</label><div><input type='text' name='name' required/></div>");
              client.println("<label>Matrikelnummer:</label><div><input type='text' name='matr' required/></div>");
              client.println("<label>Email:</label><div><input type='text' name='email' required/></div>");
              client.println("<label class='hl'>Laserauftrag</label>");
              client.println("<label>An welchem Fachbereich studierst du?</label><div><select name='fb'><option value='4' selected>FB4 - Design</option><option value='other'>Anderer FB</option></select></div>");
              client.println("<label>Ist die Arbeit im Rahmen eines Kurses entstanden?</label><div><select name='seminar'><option value='nein' selected>Nein</option><option value='ja'>Ja</option></select></div>");
              client.println("<p style='margin-top:10px;'><i>Falls es eine Kursarbeit ist:</i></p>");
              client.println("<label>Name des Lehrenden:</label><div><input type='text' name='lecturer' /></div>");
              client.println("<label>Titel des Kurses:</label><div><input type='text' name='title' /></div>");
              client.println("<div style='margin-top:20px;'><input type='submit' value='abschicken&nbsp;&raquo;'/></div>");
              client.println("</form>");
            }

            client.println("</main>");
            client.println("<footer>Bei Fragen findest du weitere Infos im <a href='https://fhp.incom.org/workspace/6508'>Laser Workspace</a>.</footer>");
            client.println("</body></html>");
            client.println();
            break;

          } else {
            currentLine = "";
          }
        } else if (c != '\r') {
          currentLine += c;
        }
      }
    }
    header = "";
    client.stop();
  }
}