#pragma once

#include <arpa/inet.h>
#include <cstdint>
#include <string>

struct Ip final {
	static const int Size = 4;

	// constructor
	Ip() {}
	Ip(const uint32_t r) : ip_(r) {}
	Ip(const std::string r);

	// casting operator
	operator uint32_t() const { return ip_; } // default
	explicit operator std::string() const;

	// comparison operator
	bool operator == (const Ip& r) const { return ip_ == r.ip_; }
	bool operator != (const Ip& r) const { return ip_ != r.ip_; }

	bool isLocalHost() const { // 127.*.*.*
		uint8_t prefix = (ip_ & 0xFF000000) >> 24;
		return prefix == 0x7F;
	}

	bool isBroadcast() const { // 255.255.255.255
		return ip_ == 0xFFFFFFFF;
	}

	bool isMulticast() const { // 224.0.0.0 ~ 239.255.255.255
		uint8_t prefix = (ip_ & 0xFF000000) >> 24;
		return prefix >= 0xE0 && prefix < 0xF0;
	}

protected:
	uint32_t ip_ = 0;
};

#pragma pack(push, 1)
struct IpHdr final {
	static const int MinSize = 20;

	enum Proto : uint8_t {
		ICMP = 1,
		TCP = 6,
		UDP = 17
	};

	uint8_t v_hl_;     // version(4) + header length(4)
	uint8_t tos_;
	uint16_t tlen_;
	uint16_t id_;
	uint16_t off_;
	uint8_t ttl_;
	uint8_t p_;
	uint16_t sum_;
	uint32_t sip_;
	uint32_t dip_;

	uint8_t version() const { return (v_hl_ >> 4) & 0x0F; }
	uint8_t hl() const { return v_hl_ & 0x0F; }
	uint8_t hlen() const { return hl() * 4; }

	uint16_t tlen() const { return ntohs(tlen_); }
	uint16_t id() const { return ntohs(id_); }
	uint16_t off() const { return ntohs(off_); }
	uint8_t ttl() const { return ttl_; }
	uint8_t p() const { return p_; }
	uint16_t sum() const { return ntohs(sum_); }

	Ip sip() const { return Ip(ntohl(sip_)); }
	Ip dip() const { return Ip(ntohl(dip_)); }
};
#pragma pack(pop)
