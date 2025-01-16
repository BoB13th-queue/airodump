#include "airodump.h"
#include <iostream>
#include <thread>
#include <csignal>
#include <pcap.h>

#define CHANNEL_HOP_INTERVAL 1

using namespace std;

static bool g_running = true;

void signal_handler(int signo) {
    (void)signo;
    g_running = false;
}

void useage(void) {
    cout << "syntax : airodump <interface>\n";
    cout << "sample : airodump mon0\n";
}

int main(int argc, char* argv[]) {
    // 채널 호핑 스레드 시작
    thread hopper(channel_hop_thread, argv[1]);

    // 패킷 캡처 루프
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if (!handle) { 
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", argv[1], errbuf);
        exit(EXIT_FAILURE);
    }

    time_t last_print = time(NULL);

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* pkt_data;
        int res = pcap_next_ex(handle, &header, &pkt_data);
        if (res == 0) continue; // timeout
        if (res == -1 || res == -2) break; // error or EOF

        // parse_packet() 호출 -> g_ap_map, g_station_map에 데이터 축적
        parse_packet(header, pkt_data);

        // 주기적으로 print_result() 호출
        time_t now = time(NULL);
        if (now - last_print >= CHANNEL_HOP_INTERVAL) { 
            print_result();
            last_print = now;
        }
    }

    // 종료 처리
    pcap_close(handle);
    hopper.join(); // 혹은 detach
    return 0;
}