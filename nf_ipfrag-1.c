#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/types.h>
#include <linux/netfilter.h>		
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <errno.h>
#include <string.h>
#include <signal.h>

# define __force

//iptables -A OUTPUT -p tcp --dport 80 -m string --algo bm --string "Host: "  -j NFQUEUE


char intf[255]; 
int rawfd;


static inline unsigned short from32to16(unsigned a) 
{
	unsigned short b = a >> 16; 
	asm("addw %w2,%w0\n\t"
	    "adcw $0,%w0\n" 
	    : "=r" (b)
	    : "0" (b), "r" (a));
	return b;
}


static inline unsigned add32_with_carry(unsigned a, unsigned b)
{
	asm("addl %2,%0\n\t"
	    "adcl $0,%0"
	    : "=r" (a)
	    : "0" (a), "rm" (b));
	return a;
}




static unsigned do_csum(const unsigned char *buff, unsigned len)
{
	unsigned odd, count;
	unsigned long result = 0;

	if (len == 0)
		return result; 
	odd = 1 & (unsigned long) buff;
	if (odd) {
		result = *buff << 8;
		len--;
		buff++;
	}
	count = len >> 1;		/* nr of 16-bit words.. */
	if (count) {
		if (2 & (unsigned long) buff) {
			result += *(unsigned short *)buff;
			count--;
			len -= 2;
			buff += 2;
		}
		count >>= 1;		/* nr of 32-bit words.. */
		if (count) {
			unsigned long zero;
			unsigned count64;
			if (4 & (unsigned long) buff) {
				result += *(unsigned int *) buff;
				count--;
				len -= 4;
				buff += 4;
			}
			count >>= 1;	/* nr of 64-bit words.. */

			/* main loop using 64byte blocks */
			zero = 0;
			count64 = count >> 3;
			while (count64) { 
				asm("addq 0*8(%[src]),%[res]\n\t"
				    "adcq 1*8(%[src]),%[res]\n\t"
				    "adcq 2*8(%[src]),%[res]\n\t"
				    "adcq 3*8(%[src]),%[res]\n\t"
				    "adcq 4*8(%[src]),%[res]\n\t"
				    "adcq 5*8(%[src]),%[res]\n\t"
				    "adcq 6*8(%[src]),%[res]\n\t"
				    "adcq 7*8(%[src]),%[res]\n\t"
				    "adcq %[zero],%[res]"
				    : [res] "=r" (result)
				    : [src] "r" (buff), [zero] "r" (zero),
				    "[res]" (result));
				buff += 64;
				count64--;
			}

			/* last up to 7 8byte blocks */
			count %= 8; 
			while (count) { 
				asm("addq %1,%0\n\t"
				    "adcq %2,%0\n" 
					    : "=r" (result)
				    : "m" (*(unsigned long *)buff), 
				    "r" (zero),  "0" (result));
				--count; 
					buff += 8;
			}
			result = add32_with_carry(result>>32,
						  result&0xffffffff); 

			if (len & 4) {
				result += *(unsigned int *) buff;
				buff += 4;
			}
		}
		if (len & 2) {
			result += *(unsigned short *) buff;
			buff += 2;
		}
	}
	if (len & 1)
		result += *buff;
	result = add32_with_carry(result>>32, result & 0xffffffff); 
	if (odd) { 
		result = from32to16(result);
		result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);
	}
	return result;
}



__wsum csum_partial(const void *buff, int len, __wsum sum)
{
	return (__force __wsum)add32_with_carry(do_csum(buff, len),
						(__force uint32_t)sum);
}



static inline __sum16 csum_fold(__wsum sum)
{
	asm("  addl %1,%0\n"
	    "  adcl $0xffff,%0"
	    : "=r" (sum)
	    : "r" ((__force uint32_t)sum << 16),
	      "0" ((__force uint32_t)sum & 0xffff0000));
	return (__force __sum16)(~(__force uint32_t)sum >> 16);
}


static inline __wsum
csum_tcpudp_nofold(__be32 saddr, __be32 daddr, unsigned short len,
		   unsigned short proto, __wsum sum)
{
	asm("  addl %1, %0\n"
	    "  adcl %2, %0\n"
	    "  adcl %3, %0\n"
	    "  adcl $0, %0\n"
	    : "=r" (sum)
	    : "g" (daddr), "g" (saddr),
	      "g" ((len + proto)<<8), "0" (sum));
	return sum;
}



static inline __sum16
csum_tcpudp_magic(__be32 saddr, __be32 daddr, unsigned short len,
		  unsigned short proto, __wsum sum)
{
	return csum_fold(csum_tcpudp_nofold(saddr, daddr, len, proto, sum));
}



void sa_hdl(int signo)
{
	system("iptables -F");
	printf("see you\n");
	sleep(3);
	exit(0);
}

/*
struct sigaction sa={
	.sa_handler = sa_hdl,
	.sa_sigaction = NULL,
	.sa_flags = 0,
	.sa_restorer = NULL
	};
*/

void * signal_(int signo, void *func)
{
	struct sigaction	act, oact;

	act.sa_handler = func;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	if (signo == SIGALRM) {
#ifdef	SA_INTERRUPT
		act.sa_flags |= SA_INTERRUPT;	/* SunOS 4.x */
#endif
	} else {
#ifdef	SA_RESTART
		act.sa_flags |= SA_RESTART;		/* SVR4, 44BSD */
#endif
	}
	if (sigaction(signo, &act, &oact) < 0)
		return(SIG_ERR);
	return(oact.sa_handler);
}
/* end signal */

void * Signal(int signo, void *func)	/* for our signal() function */
{
	void *sigfunc;

	if ( (sigfunc = signal_(signo, func)) == SIG_ERR)
		perror("signal error");
	return(sigfunc);
}


void fw()
{
	system("iptables -F");
	system("iptables -A OUTPUT -p tcp --dport 80 -m string --algo bm --string \"Host: \"  -j NFQUEUE");
	system("iptables -A FORWARD -p tcp --dport 80 -m string --algo bm --string \"Host: \"  -j NFQUEUE");
	//system("iptables -A INPUT -p tcp --sport 80 -m string --algo bm --string \"Location: http://120.52\" -j DROP"); //cu http 302 hijack
//	system("iptables -A INPUT  ! -s 192.168.0.0/16 -p tcp --sport 80 -m string --algo kmp --string \"302 Found\" -m string --algo kmp --string \"Location: http://120.52.\" -j DROP");
}

int sock_init()
{
	int ret = 0;
	int s_on = 1;
	if((rawfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) <0){
		perror("raw socket failed");
		ret = errno;
	}
/*
	if((setsockopt(rawfd, SOL_SOCKET, SO_BINDTODEVICE, intf, 6)) < 0){
		perror("set BINDTODEVICE failed");
		ret = errno;
	}
*/

	if(setsockopt(rawfd, IPPROTO_IP, IP_HDRINCL, &s_on, sizeof(s_on)) < 0){
		perror("set IP_HDRINCL failed");
		ret = errno;
	}
	return ret;
}


enum {
	PKT_ACCEPT = 0,
	PKT_DROP,
};

struct ip_pkt
{
	struct iphdr iph;
	struct tcphdr tcph;
	char u_payload[0];
};

static void dump_pkt(char *s, unsigned char *pkt, int len)
{
	int i;
	printf("%s\n", s);
	for (i=0;i<len;i++){
		if(i%20 ==0 )
			printf("\n");
		printf("%02x ", *(pkt+i));
	}
	printf("\n");
}



static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0) {
		printf("payload_len=%d ", ret);
		//processPacketData (data, ret);
		dump_pkt("payload:", data, ret);
	}
	fputc('\n', stdout);

	return id;
}

static uint16_t checksum (uint16_t *addr, int len)
{
	int count = len;
	register uint32_t sum = 0;
	uint16_t answer = 0;

	// Sum up 2-byte values until none or only one byte left.
	while (count > 1) {
	sum += *(addr++);
	count -= 2;
	}

	// Add left-over byte, if any.
	if (count > 0) {
	sum += *(uint8_t *) addr;
	}

	// Fold 32-bit sum into 16 bits; we lose information by doing this,
	// increasing the chances of a collision.
	// sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
	while (sum >> 16) {
	sum = (sum & 0xffff) + (sum >> 16);
	}

	// Checksum is one's compliment of sum.
	answer = ~sum;

	return (answer);
}

int process_pkt_1(struct nfq_q_handle *qh, struct nfq_data *nfa)
{
	u_int16_t pkt_len;
	u_int16_t pkt1_len;
	u_int16_t pkt2_len;
//	int rawfd;
	struct ip_pkt *ipk = NULL;
	struct ip_pkt *ipk2 = NULL;
	struct sockaddr_in da;
	unsigned char *data = NULL;
	unsigned char data2[3500];
	char *strloc = NULL;
	int offset;
	int tcp_seg_len;
	char request[3500] = {0,};
	u_int16_t tcp_hdr_len = 0;

	u_int32_t id;
        struct nfqnl_msg_packet_hdr *ph;
	ph = nfq_get_msg_packet_hdr(nfa);	
	id = ntohl(ph->packet_id);

	pkt_len = nfq_get_payload(nfa, &data);
	ipk = (struct ip_pkt *)data;
	ipk2 = (struct ip_pkt *)data2;

//	printf("ttl:%u\n", (ipk->iph).ttl);

	if((ipk->iph).ttl == 199){
		ipk->iph.ttl = 199;
		ipk->iph.check = 0;
		ipk->iph.check = checksum((uint16_t *)data, 20);
		nfq_set_verdict(qh, id, NF_ACCEPT, pkt_len, data);
		printf("pass\n");
		return PKT_ACCEPT;
	}
	
	tcp_hdr_len = ipk->tcph.th_off * 4;

	if(strloc = strstr((char *)ipk+20+tcp_hdr_len, "GET")){
//		offset = strloc-ipk->u_payload;
		offset = strloc-(char *)data;
		if(ntohs(ipk->iph.tot_len)-offset<=0){			//扫到上次缓冲区残馀数据的部分
			nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
			printf("offset\n");
			return PKT_ACCEPT;
		}
		strncpy(request, strloc, ntohs(ipk->iph.tot_len)-offset);
		printf("tcp_request:%s, str_tcp_offset:%d\n", request, offset);
		memset(request, 0, 3500);
	}else{
		printf("not found\n");	
		nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
		return PKT_ACCEPT;
	}
//	offset += 5; //skip "GET "
	offset += 2; //split "GET " to avoid censorship
	memcpy(data2, data, pkt_len);
	pkt1_len = offset;
	pkt2_len = ntohs(ipk->iph.tot_len) - offset + 20 + tcp_hdr_len;
	memcpy(data2+20+tcp_hdr_len, data+pkt1_len, ntohs(ipk->iph.tot_len)-offset);

	ipk->iph.ttl = 199;
	ipk->iph.tot_len = htons(pkt1_len);
	ipk->iph.check = 0;
	ipk->iph.check = checksum((uint16_t *)data, 20);
	ipk->tcph.th_sum = 0;
	ipk->tcph.th_sum = csum_tcpudp_magic(ipk->iph.saddr,
				ipk->iph.daddr,
				pkt1_len-20, IPPROTO_TCP,
				csum_partial((unsigned char *)(&ipk->tcph), pkt1_len-20, 0));

	ipk2->iph.ttl = 199;
	ipk2->iph.tot_len = htons(pkt2_len);
	ipk2->iph.check = 0;
	ipk2->iph.check = checksum((uint16_t *)data2, 20);
	ipk2->tcph.th_seq = htonl(ntohl(ipk->tcph.th_seq)+(pkt1_len - 20 - tcp_hdr_len));
	ipk2->tcph.th_sum = 0;
	ipk2->tcph.th_sum = csum_tcpudp_magic(ipk2->iph.saddr,
				ipk2->iph.daddr,
				pkt2_len-20, IPPROTO_TCP,
				csum_partial((unsigned char *)(&ipk2->tcph), pkt2_len-20, 0));

	memset(&da, 0, sizeof(struct sockaddr));
	da.sin_addr.s_addr = (ipk->iph).daddr;

		printf("pkt1_len:%d\n", pkt1_len);
		printf("pkt2_len:%d\n", pkt2_len);
	if(sendto(rawfd, data, pkt1_len, 0, (struct sockaddr *)&da, sizeof(struct sockaddr)) < 0){
		perror("sendto1 failed");
		printf("pkt1_len:%d\n", pkt1_len);
		exit(errno);
	}
    usleep(400000);
	if(sendto(rawfd, data2, pkt2_len, 0, (struct sockaddr *)&da, sizeof(struct sockaddr)) < 0){
		perror("sendto2 failed");
		printf("pkt2_len:%d\n", pkt2_len);
		exit(errno);
	}


//	sleep(4);

//	close(rawfd);
	nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	return PKT_DROP;
}
	
int process_pkt(struct nfq_q_handle *qh, struct nfq_data *nfa)
{
	u_int16_t pkt_len;
	u_int16_t pkt1_len;
	u_int16_t pkt2_len;
//	int rawfd;
	struct ip_pkt *ipk = NULL;
	struct ip_pkt *ipk2 = NULL;
	struct sockaddr_in da;
	unsigned char *data = NULL;
	unsigned char data2[3500];
	char *strloc = NULL;
	int offset;
	int tcp_seg_len;
	char request[3500] = {0,};
	u_int16_t tcp_hdr_len = 0;

	u_int32_t id;

        struct nfqnl_msg_packet_hdr *ph;
	ph = nfq_get_msg_packet_hdr(nfa);	
	id = ntohl(ph->packet_id);

	pkt_len = nfq_get_payload(nfa, &data);
	ipk = (struct ip_pkt *)data;
	ipk2 = (struct ip_pkt *)data2;

//	printf("ttl:%u\n", (ipk->iph).ttl);

	if((ipk->iph).ttl == 199){
		ipk->iph.ttl = 199;
		ipk->iph.check = 0;
		ipk->iph.check = checksum((uint16_t *)data, 20);
		nfq_set_verdict(qh, id, NF_ACCEPT, pkt_len, data);
		return PKT_ACCEPT;
	}
	
	tcp_hdr_len = ipk->tcph.th_off * 4;


	
//	printf("tcp hdr len:%d\n", tcp_hdr_len);
	printf("pkt_len:%d, ip tot len:%d\n",pkt_len, ntohs(ipk->iph.tot_len));
//	dump_pkt("payload:", data, pkt_len);
	
	if(strloc = strstr((char *)ipk+20+tcp_hdr_len, "Host:")){
//		offset = strloc-ipk->u_payload;
		offset = strloc-(char *)data;
		if(ntohs(ipk->iph.tot_len)-offset<=0){			//扫到上次缓冲区残馀数据的部分
			nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
			return PKT_ACCEPT;
		}
		strncpy(request, strloc, ntohs(ipk->iph.tot_len)-offset);
		printf("tcp_request:%s, str_tcp_offset:%d\n", request, offset);
		memset(request, 0, 3500);
	}else{
		
		nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
		return PKT_ACCEPT;
	}

//	offset = 16; //debug
//	offset &= 0x1f8;
	offset += 5; //skip "host: "
	tcp_seg_len = ((offset-20)>>3)<<3;
	memcpy(data2, data, pkt_len);
	pkt1_len = 20 + tcp_seg_len;
	pkt2_len = ntohs(ipk->iph.tot_len)-pkt1_len;
	memcpy(data2+20, data+pkt1_len, pkt2_len);
	pkt2_len += 20;   //add another ip hdr

	ipk->iph.frag_off = htons(0x20<<8); //DF flag
	ipk->iph.ttl = 199;
	ipk->iph.tot_len = htons(pkt1_len);
	ipk->iph.check = 0;
	ipk->iph.check = checksum((uint16_t *)data, 20);

	ipk2->iph.frag_off = htons(0x40<<8|(tcp_seg_len>>3));
	ipk2->iph.ttl = 199;
	ipk2->iph.tot_len = htons(pkt2_len);
	ipk2->iph.check = 0;
	ipk2->iph.check = checksum((uint16_t *)data2, 20);

//	dump_pkt("payload1:", data, pkt1_len);
//	dump_pkt("payload2:", data2, pkt2_len);
	
/*
	if((rawfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) <0){
		perror("raw socket failed");
		exit(errno);
	}

	if((setsockopt(rawfd, SOL_SOCKET, SO_BINDTODEVICE, intf, 6)) < 0){
		perror("set BINDTODEVICE failed");
		exit(errno);
	}

	if(setsockopt(rawfd, IPPROTO_IP, IP_HDRINCL, &s_on, sizeof(s_on)) < 0){
		perror("set IP_HDRINCL failed");
		exit(errno);
	}
*/

	memset(&da, 0, sizeof(struct sockaddr));
	da.sin_addr.s_addr = (ipk->iph).daddr;

	if(sendto(rawfd, data2, pkt2_len, 0, (struct sockaddr *)&da, sizeof(struct sockaddr)) < 0){
		perror("sendto2 failed");
		printf("pkt2_len:%d\n", pkt2_len);
		exit(errno);
	}

//	sleep(4);

	if(sendto(rawfd, data, pkt1_len, 0, (struct sockaddr *)&da, sizeof(struct sockaddr)) < 0){
		perror("sendto1 failed");
		printf("pkt1_len:%d\n", pkt2_len);
		exit(errno);
	}


//	close(rawfd);
	nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	return PKT_DROP;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
//	u_int32_t id = print_pkt(nfa);
	int ret = 0;
/*
	u_int32_t id;

        struct nfqnl_msg_packet_hdr *ph;
	ph = nfq_get_msg_packet_hdr(nfa);	
	id = ntohl(ph->packet_id);
*/

//	ret = process_pkt(qh, nfa);
	ret = process_pkt_1(qh, nfa);
/*
	if(ret == PKT_ACCEPT){
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}
	if(ret == PKT_DROP){
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	}
*/
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

//	printf("opening library handle\n");

	if(argc < 2){
		perror("no interface found");
		exit(0);
	}
	strcpy(intf, argv[1]);
	if(sock_init()){
		exit(0);
	}

	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

//	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

//	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

//	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

//	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fw();
/*
	sigemptyset(&sa.sa_mask);
	if(sigaction(SIGINT, &sa, NULL)){
		perror("sigaction");
		exit(0);
	}
	if(sigaction(SIGTERM, &sa, NULL)){
		perror("sigaction");
		exit(0);
	}
*/
	
	Signal(SIGINT, &sa_hdl);
	Signal(SIGTERM, &sa_hdl);

	fd = nfq_fd(h);

	// para el tema del loss:   while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0)

	while ((rv = recv(fd, buf, sizeof(buf), 0)))
	{
		printf("##pkt received\n");
		nfq_handle_packet(h, buf, rv);
//		dump_pkt("payload_full:", buf, rv);
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
