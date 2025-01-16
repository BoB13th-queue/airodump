#include <iostream>
#include <cstdio>
#include <cstring>
#include <arpa/inet.h>

#include "airodump.h"
#include "radiotap.h"
#include "ieee80211.h"

#ifndef WLAN_CAPABILITY_PRIVACY
#define WLAN_CAPABILITY_PRIVACY 0x0010
#endif

static const uint8_t RSN_OUI[3] = {0x00, 0x0F, 0xAC};
static const uint8_t WPA_OUI[3] = {0x00, 0x50, 0xF2};

void parse_packet(const struct pcap_pkthdr *header, const u_char *packet) {
    if (!header || !packet) {
        return;
    }

    // 전역 맵에 접근해야 하므로 lock_guard 사용
    std::lock_guard<std::mutex> lock(g_data_mutex);

    // Radiotap 헤더 파싱
    const ieee80211_radiotap_header *rtap =
        reinterpret_cast<const ieee80211_radiotap_header *>(packet);
    uint16_t radiotap_len = rtap->it_len;

    // 802.11 헤더 시작 위치
    const ieee80211_frame *wifi =
        reinterpret_cast<const ieee80211_frame *>(packet + radiotap_len);

    // Frame Control 필드에서 Type/Subtype 추출
    uint8_t fc0 = wifi->i_fc[0];
    // uint8_t fc1 = wifi->i_fc[1]; // 필요 시 사용

    uint8_t type    = fc0 & IEEE80211_FC0_TYPE_MASK;
    uint8_t subtype = fc0 & IEEE80211_FC0_SUBTYPE_MASK;

    // ---- 여기서부터 모든 로직에서 참조할 변수들 ----
    // Beacon인지 아닌지에 따라 내용이 달라질 수 있으므로, 기본값으로 초기화
    std::string bssid_str; 
    int8_t rssi = -100; // 일단 -100으로 초기화 (실제로는 Radiotap에서 추출)

    
    if (type == IEEE80211_FC0_TYPE_MGT && subtype == IEEE80211_FC0_SUBTYPE_BEACON){
        // BSSID
        uint8_t bssid_mac[6];
        std::memcpy(bssid_mac, wifi->i_addr3, 6);
        bssid_str = mac_to_string(bssid_mac);

        // (간단 예시) RSSI = -60 (실제로는 radiotap it_present 파싱)
        rssi = -60;

        // 매니지먼트 헤더(24byte) + 고정 파라미터(12byte)
        const uint8_t *mgmt_body = reinterpret_cast<const uint8_t *>(wifi) + 24;
        // Capability Info (Little Endian)
        uint16_t capab = (mgmt_body[10] | (mgmt_body[11] << 8));

        // Tagged Parameter 시작
        const uint8_t *tagged_params = mgmt_body + 12;
        const uint8_t *packet_end = packet + header->caplen;

        // ENC 판별용 변수
        bool isWEP  = false;
        bool isWPA  = false;
        bool isWPA2 = false;

        // Cipher/Auth
        std::string cipher_str;
        std::string auth_str;

        // SSID
        std::string essid;

        // Privacy 비트 -> WEP 이상
        if (capab & WLAN_CAPABILITY_PRIVACY) {
            isWEP = true;
        }

        // 태그 파싱 (switch-case)
        while (tagged_params + 2 < packet_end) {
            uint8_t tag_number = tagged_params[0];
            uint8_t tag_length = tagged_params[1];
            const uint8_t *tag_value = tagged_params + 2;

            if (tag_value + tag_length > packet_end) {
                break;
            }

            switch (tag_number) {
                case 0: {
                    // SSID
                    if (tag_length > 0) {
                        essid.assign(reinterpret_cast<const char*>(tag_value), tag_length);
                    } else {
                        essid = "<hidden SSID>";
                    }
                } break;
                case 48: {
                    // RSN = WPA2
                    isWPA2 = true;
                    isWEP  = false;

                    // 간단 예시
                    if (tag_length >= 6) {
                        const uint8_t *group_oui = tag_value + 2; // OUI
                        uint8_t group_cipher_type = *(tag_value + 5);
                        if (!std::memcmp(group_oui, RSN_OUI, 3)) {
                            switch (group_cipher_type) {
                                case 2:  cipher_str = "TKIP"; break;
                                case 4:  cipher_str = "CCMP"; break;
                                default: cipher_str = "??";   break;
                            }
                        }
                    }
                    auth_str = "PSK";
                } break;
                case 221: {
                    // Vendor Specific -> WPA 가능성 (OUI=00:50:F2, Type=1)
                    if (tag_length >= 4) {
                        if (!std::memcmp(tag_value, WPA_OUI, 3) && tag_value[3] == 0x01) {
                            isWPA  = true;
                            isWEP  = false;

                            cipher_str = "TKIP";
                            auth_str   = "PSK";
                        }
                    }
                } break;
                default:
                    break;
            }

            tagged_params += (2 + tag_length);
        }

        // ENC 문자열 결정
        std::string enc_str;
        if (isWPA2) {
            enc_str = "WPA2";
        } else if (isWPA) {
            enc_str = "WPA";
        } else if (isWEP) {
            enc_str = "WEP";
        } else {
            enc_str = "OPN";
        }

        std::string final_enc = enc_str;
        if (!cipher_str.empty()) final_enc += " " + cipher_str;
        if (!auth_str.empty())   final_enc += " " + auth_str;

        // ---- 맵 갱신 (AP 정보) ----
        auto it = g_ap_map.find(bssid_str);
        if (it == g_ap_map.end()) {
            // 새 AP
            ap_info ap;
            ap.bssid        = bssid_str;
            ap.pwr          = rssi;
            ap.beacon_count = 1;
            ap.data_count   = 0;
            ap.channel      = g_current_channel.load();
            ap.essid        = essid;
            ap.enc          = final_enc;

            g_ap_map[bssid_str] = ap;
        } else {
            // 기존 AP 업데이트
            it->second.pwr = rssi;
            it->second.beacon_count++;
            if (it->second.essid.empty()) {
                it->second.essid = essid;
            }
            it->second.enc = final_enc;
        }
    }
    
    // ---- 스테이션(클라이언트) 처리 (예시) ----
    // 여기서 bssid_str, rssi는 Beacon이 아닐 경우 기본값(빈 문자열, -100)일 수 있음
    // 실제로는 Data/Probe Request일 때 STA MAC을 처리하는 로직이 더 적절할 수 있습니다.
    std::string sta_str = mac_to_string(wifi->i_addr2);
    auto st_it = g_station_map.find(sta_str);
    if (st_it == g_station_map.end()) {
        station_info st;
        st.mac   = sta_str;
        st.bssid = bssid_str; // 이 예시에선 "같은 BSSID"로 연결 중이라 가정
        st.pwr   = rssi;
        st.probes= "SomeProbeSSID";

        g_station_map[sta_str] = st;
        st_it = g_station_map.find(sta_str);
    }
    // 스테이션 정보 업데이트
    st_it->second.pwr = rssi;
}
