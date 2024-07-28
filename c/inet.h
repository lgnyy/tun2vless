
#pragma once

#include <stdint.h>

struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    uint8_t    ihl:4,
            version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
    uint8_t    version:4,
            ihl:4;
#else
#error "Please fix "
#endif
    uint8_t    tos;
    uint16_t tot_len;
    uint16_t id;
    // flag����Ϊ3 λ,��Ŀǰֻ��2λ������. 
    // ��־�ֶ��е����λ��Ϊ MF(More Fragment).MF=1����ʾ����"���з�Ƭ"�����ݱ�.MF=0��ʾ�������������ݱ�Ƭ�е����һ��.
    // ��־�ֶ��м��һλ��ΪDF(Don��t Fragment),��˼��"���ܷ�Ƭ",ֻ�е� DF=0ʱ�������Ƭ.
    uint16_t frag_off;
    uint8_t    ttl;
    uint8_t    protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

struct tcphdr {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
    uint16_t   res1:4,
            doff:4,
            fin:1,
            syn:1,
            rst:1,
            psh:1,
            ack:1,
            urg:1,
            ece:1,
            cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
    uint16_t   doff:4,
            res1:4,
            cwr:1,
            ece:1,
            urg:1,
            ack:1,
            psh:1,
            rst:1,
            syn:1,
            fin:1;
#else
#error "Adjust your <asm/byteorder.h> defines"
#endif
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
};

struct udphdr {
  uint16_t source;
  uint16_t dest;
  uint16_t length;
  uint16_t check;
};

/**
 * IP checksum calculation.
 * Following RFC 1071.
 * In essence 1's complement of 16-bit groups.
 */
static uint16_t inet_checksum(uint32_t sum, const uint8_t* addr, int nbytes) {
  for (; nbytes > 1; nbytes -= 2, addr += 2) {
    sum += *(uint16_t*)addr;
  }
  if (nbytes > 0) {
    uint8_t tmp[2] = { *addr, 0x00 };
    sum += *(uint16_t*)addr;
  }

  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }
  return (uint16_t)(~sum);
}
static uint16_t ip_checksum(const uint8_t* addr, int nbytes) {
  return inet_checksum(0, addr, nbytes);
}
static uint16_t tcp_checksum(const struct tcphdr* tcp, const void* data_ptr, size_t data_len) {
  const struct iphdr* ip = ((struct iphdr*)tcp) - 1;
  size_t nbytes = (tcp->doff << 2) + data_len;
  uint16_t* tmp = (uint16_t*)&(ip->saddr);
  uint8_t ptcl[2] = { 0, ip->protocol };
  uint8_t tcpl[2] = { (nbytes >> 8) & 0xFF, (nbytes & 0xFF) }; // ntohs
  // α�ײ�
  uint32_t sum = tmp[0] + tmp[1] + tmp[2] + tmp[3] + *((uint16_t*)ptcl) + *((uint16_t*)tcpl);
  // tcp
  if (data_len > 0) {
    const uint8_t* addr = (const uint8_t*)tcp;
    nbytes -= data_len;
    for (; nbytes > 1; nbytes -= 2, addr += 2) {
      sum += *(uint16_t*)addr;
    }
    return inet_checksum(sum, (const uint8_t*)data_ptr, (int)data_len);
  }
  else {
    return inet_checksum(sum, (const uint8_t*)tcp, (int)nbytes);
  }
}

static uint16_t udp_checksum(const struct udphdr* udp, const void* data_ptr, size_t data_len) {
  const struct iphdr* ip = ((struct iphdr*)udp) - 1;
  size_t nbytes = 12 + data_len;
  uint16_t* tmp = (uint16_t*)&(ip->saddr);
  uint8_t ptcl[2] = { 0, ip->protocol };
  uint8_t tcpl[2] = { (nbytes >> 8) & 0xFF, (nbytes & 0xFF) }; // ntohs
  // α�ײ�
  uint32_t sum = tmp[0] + tmp[1] + tmp[2] + tmp[3] + *((uint16_t*)ptcl) + *((uint16_t*)tcpl);
  // udp
  const uint8_t* addr = (const uint8_t*)udp;
  nbytes = 12;
  for (; nbytes > 1; nbytes -= 2, addr += 2) {
    sum += *(uint16_t*)addr;
  }
  return inet_checksum(sum, (const uint8_t*)data_ptr, (int)data_len);
}

#define inet_get_tcp(ip) (struct tcphdr*)(((uint8_t*)(ip)) + ((ip)->ihl << 2))
#define inet_get_udp(ip) (struct udphdr*)(((uint8_t*)(ip)) + ((ip)->ihl << 2))