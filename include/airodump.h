#ifndef AIRODUMP_H
#define AIRODUMP_H

#include <pcap.h>
#include <string>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <cstdint>

using namespace std;

// AP 정보
struct ap_info {
    string bssid;      // "XX:XX:XX:XX:XX:XX"
    int8_t pwr;
    unsigned int beacon_count;
    unsigned int data_count;
    int channel;
    string essid;
    string enc;
};

// Station 정보
struct station_info {
    string mac;        // "XX:XX:XX:XX:XX:XX"
    string bssid;      // 연결된 AP BSSID
    int8_t pwr;
    string probes;
};

// 전역 맵 (BSSID->AP Info, Station MAC->Station Info)
extern unordered_map<string, ap_info>    g_ap_map;
extern unordered_map<string, station_info> g_station_map;

// 전역 mutex
extern mutex g_data_mutex;

// 현재 채널 
extern atomic<int> g_current_channel;

// 함수 선언
void channel_hop_thread(const char *ifname);
void parse_packet(const struct pcap_pkthdr *header, const u_char *packet);
void print_result();
string mac_to_string(const uint8_t mac[6]);

#endif // AIRODUMP_H
