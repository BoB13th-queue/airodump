#include <iostream>
#include <iomanip>   // for setw
#include <sstream>
#include <thread>    // this_thread::sleep_for
#include <chrono>    // chrono::seconds
#include <cstring>   // memcpy, memset
#include <unistd.h>  // close, usleep
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/wireless.h>

#include "airodump.h"

#define HOP_INTERVAL 1

using namespace std;

// ==== 전역 변수 정의 ====
unordered_map<string, ap_info>    g_ap_map;
unordered_map<string, station_info> g_station_map;
mutex g_data_mutex;
atomic<int> g_current_channel(0);

// MAC 배열 -> 문자열 변환
string mac_to_string(const uint8_t mac[6]) {
    ostringstream oss;
    // 2자리 헥사값 + ':'를 6번 반복
    oss << hex << setw(2) << setfill('0') << (int)mac[0];
    for (int i = 1; i < 6; i++) {
        oss << ":" << setw(2) << setfill('0') << (int)mac[i];
    }
    return oss.str();
}

void channel_hop_thread(const char *ifname) {
    static int ch_list[] = {1,2,3,4,5,6,7,8,9,10,11,12,13};
    int idx = 0;

    while (true) {
        // 채널 목록에서 현재 채널 가져오기
        int ch = ch_list[idx];
        {
            // 전역 데이터 보호(뮤텍스 잠금) -- 
            // g_current_channel 같은 전역 변수를 건드릴 때 동시접근 방지
            lock_guard<mutex> lock(g_data_mutex);

            struct iwreq wrq;
            int sock = socket(AF_INET, SOCK_DGRAM, 0);
            if (sock < 0) {
                perror("socket");
            } else {
                memset(&wrq, 0, sizeof(wrq));
                strncpy(wrq.ifr_name, ifname, IFNAMSIZ);
                wrq.u.freq.m = ch;
                wrq.u.freq.e = 0;
                if (ioctl(sock, SIOCSIWFREQ, &wrq) < 0) {
                    perror("ioctl(SIOCSIWFREQ)");
                }
                close(sock);
            }

            // 전역 채널 값 갱신
            g_current_channel.store(ch);
        }

        // 다음 채널 인덱스
        idx = (idx + 3) % (sizeof(ch_list) / sizeof(ch_list[0]));

        this_thread::sleep_for(chrono::seconds(HOP_INTERVAL));
    }
}

void print_result() {
    #ifdef __linux__
        system("clear");
    #elif _WIN32
        system("cls");
    #endif

    // Lock for thread-safe reading of global maps
    lock_guard<mutex> lock(g_data_mutex);

    int current_ch = g_current_channel.load();

    // 간단히 현재 시간 문자열 생성
    time_t now = time(nullptr);
    tm *tm_struct = localtime(&now);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M", tm_struct);

    cout << "\n[ CH " << current_ch << " ] [ Elapsed: 0 s ] [ "
              << time_str << " ]\n" << endl;

    // AP 목록 테이블 헤더
    cout << " BSSID              "
        << "  " << setw(4) << "PWR"
        << "  " << setw(8) << "Beacons"
        << "  " << setw(5) << "#Data"
        << "  " << setw(2) << "CH"
        << "  " << setw(8) << "ENC"
        << "  " << "ESSID"
        << endl;

    // AP 맵 순회
    for (auto &kv : g_ap_map) {
        const ap_info &ap = kv.second;
        // 한 줄 출력 (예시 포맷)
        cout 
            << " " << setw(17) << left  << ap.bssid    // BSSID 17자 폭, 좌측정렬
            << "  " << setw(4)  << right << (int)ap.pwr  // PWR 4자 폭, 우측정렬
            << "  " << setw(8)  << right << ap.beacon_count
            << "  " << setw(5)  << right << ap.data_count
            << "  " << setw(2)  << right << ap.channel
            << "  " << setw(8)  << left  << ap.enc     // ENC 8자 폭, 좌측정렬
            << "  " << ap.essid                             // ESSID는 남은 공간 그대로 출력
            << endl;
    }

    cout << "\n BSSID              STATION            PWR    Probes" << endl;
    cout << endl;

    // Station 맵 순회
    for (auto &kv : g_station_map) {
        const station_info &st = kv.second;
        cout 
            << " " << setw(17) << left << st.bssid
            << "   " << setw(17) << left << st.mac
            << "   " << (int)st.pwr
            << "    " << st.probes
            << endl;
    }

    cout << endl;
}
