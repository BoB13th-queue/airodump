#ifndef IEEE80211_H
#define IEEE80211_H

#include <cstdint>

/* 802.11 무선 프레임 헤더 */
#pragma pack(push, 1)
struct ieee80211_frame {
    uint8_t i_fc[2];    // Frame Control
    uint8_t i_dur[2];   // Duration
    uint8_t i_addr1[6]; // 수신 대상(MAC)
    uint8_t i_addr2[6]; // 송신자(MAC)
    uint8_t i_addr3[6]; // BSSID(주로 AP의 MAC)
    uint16_t i_seq;     // Sequence Control
    // i_addr4 등은 생략
};
#pragma pack(pop)

/* Frame Control 필드를 파싱하기 위한 마스크 */
#define IEEE80211_FC0_TYPE_MASK      0x0c
#define IEEE80211_FC0_TYPE_MGT       0x00
#define IEEE80211_FC0_TYPE_CTRL      0x04
#define IEEE80211_FC0_TYPE_DATA      0x08

/* Subtype 마스크 */
#define IEEE80211_FC0_SUBTYPE_MASK   0xf0

#define IEEE80211_FC0_SUBTYPE_BEACON     0x80
#define IEEE80211_FC0_SUBTYPE_PROBE_REQ  0x40
#define IEEE80211_FC0_SUBTYPE_PROBE_RESP 0x50
// 필요한 subtype 정의 추가

#endif // IEEE80211_H
