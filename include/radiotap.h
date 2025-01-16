#ifndef RADIOTAP_H
#define RADIOTAP_H

#include <cstdint>

/*
 * Radiotap 기본 헤더
 * https://www.radiotap.org/
 */
#pragma pack(push, 1)
struct ieee80211_radiotap_header {
    uint8_t  it_version; // Set to 0
    uint8_t  it_pad;
    uint16_t it_len;     // 전체 길이
    uint32_t it_present; // 필드 비트맵
};
#pragma pack(pop)

/* radiotap 비트매핑(예시) */
#ifndef IEEE80211_RADIOTAP_TSFT
#define IEEE80211_RADIOTAP_TSFT            0x00000001
#endif
#ifndef IEEE80211_RADIOTAP_FLAGS
#define IEEE80211_RADIOTAP_FLAGS           0x00000002
#endif
#ifndef IEEE80211_RADIOTAP_RATE
#define IEEE80211_RADIOTAP_RATE            0x00000004
#endif
#ifndef IEEE80211_RADIOTAP_CHANNEL
#define IEEE80211_RADIOTAP_CHANNEL         0x00000008
#endif
#ifndef IEEE80211_RADIOTAP_DBM_ANTSIGNAL
#define IEEE80211_RADIOTAP_DBM_ANTSIGNAL   0x00000020
#endif

#endif // RADIOTAP_H
