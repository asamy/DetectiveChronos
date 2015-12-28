/*
 * Copyright (c) 2015 Ahmed Samy  <f.fallen45@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include <net/if.h>
#include <net/if_arp.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_fddi.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <time.h>
#include <unistd.h>
#include <errno.h>

/* Fake header.  */
struct timestamp_hdr {
	uint32_t orig;
	uint32_t recv;
	uint32_t xmit;
};

#define SNIFF_TIMEOUT		100
#define IP_ICMP_COMBINED 	sizeof(struct iphdr) + sizeof(struct icmphdr)
#define PACKET_LENGTH		IP_ICMP_COMBINED + sizeof(struct timestamp_hdr)

struct packet {
	struct iphdr *ip;
	struct icmphdr *icmp;
	uint8_t off;
	uint8_t buf[PACKET_LENGTH];
};

static bool next_packet(int fd, struct packet *p)
{
	struct sockaddr_ll fromaddr;
	socklen_t fromlen = sizeof(fromaddr);

	fd_set fdset;
	struct timeval tv;
	int c;

	FD_ZERO(&fdset);
	FD_SET(fd, &fdset);

	tv.tv_sec = 0;
	tv.tv_usec = SNIFF_TIMEOUT * 1000;

	errno = 0;
	do
		c = select(fd + 1, &fdset, NULL, NULL, &tv);
	while (c == -1 && errno == EINTR);
	if (c == -1 || !FD_ISSET(fd, &fdset))
		return false;

	if (recvfrom(fd, p->buf, PACKET_LENGTH, 0, (struct sockaddr *)&fromaddr, &fromlen) == 0)
		return false;

	switch (fromaddr.sll_hatype) {
	case ARPHRD_ETHER:
	case ARPHRD_LOOPBACK:
		p->off = ETH_HLEN;
		break;
	case ARPHRD_FRAD:
	case ARPHRD_DLCI:
		p->off = 4;
		break;
	case ARPHRD_FDDI:
	case ARPHRD_IEEE802:
	case ARPHRD_IEEE802_TR:
	case ARPHRD_HDLC:
		p->off = 18;
		break;
	case ARPHRD_SLIP:
	case ARPHRD_CSLIP:
	case ARPHRD_SLIP6:
	case ARPHRD_CSLIP6:
	case ARPHRD_PPP:
	case ARPHRD_TUNNEL:	
	default:
		p->off = 0;
		break;
	}

	p->ip = (struct iphdr *)(p->buf + p->off);
	if (p->ip->protocol != IPPROTO_ICMP)
		return false;

	p->ip->tot_len = htons(p->ip->tot_len);
	p->ip->id = htons(p->ip->id);
	p->icmp = (struct icmphdr *)((uintptr_t)p->ip + p->ip->ihl * 4);
	return true;
}

static int msec_since_midnight(void)
{
	struct timeval tv;
	if (gettimeofday(&tv, NULL) == 0)
		return ((tv.tv_sec % 86400) * 1000 + tv.tv_usec / 1000);
	return -1;
}

static uint16_t hdr_checksum(register const uint16_t *buf, register int length)
{
	register uint32_t sum = 0;
	while (length > 1) {
		sum += *buf++;
		length -= 2;
	}

	if (length == 1)
		sum += *buf;

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	return (uint16_t)~sum;
}

/* send an ICMP timestamp request, returns sequence id to be matched later.   */
static int send_icmp(int fd, uint32_t src, uint32_t dst)
{
	static int last_seq = 0;

	char *packet = malloc(PACKET_LENGTH);
	if (!packet)
		return -1;

	struct sockaddr_in to;
	to.sin_family = AF_INET;
	to.sin_addr.s_addr = dst;

	struct iphdr *ip = (struct iphdr *)packet;
	ip->version = 0x04;
	ip->ihl = 0x05;
	ip->tos = 0x00;
	ip->id = htons(0x5533);
	ip->tot_len = htons(PACKET_LENGTH);
	ip->ttl = 0xFF;
	ip->protocol = IPPROTO_ICMP;
	ip->saddr = src;
	ip->daddr = dst;

	/* IP checksum  */
	ip->check = 0;
	ip->check = hdr_checksum((const uint16_t *)ip, sizeof(struct iphdr));

	struct icmphdr *icmp = (struct icmphdr *)(packet + sizeof(struct iphdr));
	icmp->type = ICMP_TIMESTAMP;
	icmp->code = 0;
	icmp->un.echo.id = 0x3F5F;
	icmp->un.echo.sequence = last_seq;

	struct timestamp_hdr *ts = (struct timestamp_hdr *)(packet + IP_ICMP_COMBINED);
	ts->orig = htonl(msec_since_midnight());
	ts->recv = 0;
	ts->xmit = 0;

	/* ICMP checksum  */
	icmp->checksum = 0;
	icmp->checksum = hdr_checksum((const uint16_t *)icmp, sizeof(*icmp) + sizeof(*ts));

	int s = sendto(fd, packet, PACKET_LENGTH, 0, (struct sockaddr *)&to, sizeof(struct sockaddr));
	free(packet);

	if (s != PACKET_LENGTH) {
		fprintf(stderr, "warning: unable to send entire packet, sent: %d, expected: %d\n", s, PACKET_LENGTH);
		return -1;
	}

	return last_seq++;
}

static bool process_packet(const struct packet *p, uint32_t src, uint32_t dst, int sequence)
{
	struct iphdr *ip = p->ip;
	if (ip->saddr != dst || ip->daddr != src) {
		printf("reply: src/dst mismatch, %d %d and %d %d\n",
			ip->saddr, ip->daddr,
			src, dst);
		return false;
	}

	struct icmphdr *icmp = p->icmp;
	if (icmp->type != ICMP_TIMESTAMPREPLY) {
		printf("reply: icmp->type != ICMP_TIMESTAMPREPLY (%d)\n",
				icmp->type);
		return false;
	}

	if (icmp->un.echo.sequence != sequence) {
		printf("reply: sequence mismatch, got %d expected %d\n",
				icmp->un.echo.sequence, sequence);
		return false;
	}

	struct timestamp_hdr *ts = (struct timestamp_hdr *)((uintptr_t)icmp + sizeof(*icmp));
	printf("reply: tot: %d orig %d recv %d xmit %d\n",
			ip->tot_len,
			ntohl(ts->orig),
			ntohl(ts->recv),
			ntohl(ts->xmit));
	return true;
}

int main(int argc, char *argv[])
{
	if (argc != 4) {
		fprintf(stderr, "%s: Usage <interface> <source host> <target host>\n",
				argv[0]);
		fprintf(stderr, "%s: e.g. %s eth0 127.0.0.1 123.456.789.9\n",
				argv[0], argv[0]);
		return 1;
	}

	char *iface = argv[1];
	char *source = argv[2];
	char *target = argv[3];
	int ret = 1;
	int fd;

	fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (fd < 0) {
		fprintf(stderr, "%s: failed to create send socket!\n", argv[0]);
		return 1;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, iface, strlen(iface)) == -1) {
		fprintf(stderr, "%s: failed to bind send socket to interface %s\n",
				argv[0], iface);
		goto err;
	}

	/* If we can't set our custom header, then it's fine,
	 * the kernel will put it's own header in there.
	 * just warn and keep going.  */
	int inc_hdr = 1;
	if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, (char *)&inc_hdr, sizeof(inc_hdr)) == -1) {
		fprintf(stderr, "%s: warning: failed to set flag include header on send socket\n",
				argv[0]);
	}

	uint32_t src = inet_addr(source);
	uint32_t dst = inet_addr(target);
	ret = send_icmp(fd, src, dst);
	if (ret < 0)
		goto err;

	/* Wait for response.  */
	struct packet p;
	for (;;) {
		if (!next_packet(fd, &p)) {
			fprintf(stderr, "unable to sniff packet, sleeping\n");
			usleep(10000);
			continue;
		}

		if (process_packet(&p, src, dst, ret)) {
			ret = 0;
			break;
		}

		fprintf(stderr, "warning: unable to process packet, sleeping\n");
		usleep(10000);
	}

err:
	close(fd);
	return ret;
}

