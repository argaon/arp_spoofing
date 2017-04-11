#include <cstdio>
#include <cstring>
#include <pcap.h>
#include <arpa/inet.h>//ip -> bin

#define PCAP_OPENFLAG_PROMISCUOUS   1   // Even if it isn't my mac, receive packet
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
void arp_reply(const char *dev,const char *snd_ip,const char *snd_mac,const char *trg_ip,const char *trg_mac)
{
    struct my_hdr mh;
    struct _ether_hdr *eh = &mh.eh;
    struct _arp_hdr *ah = &mh.ah;

    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];

    if ( (fp= pcap_open_live(dev, 42, PCAP_OPENFLAG_PROMISCUOUS , 1000, errbuf)) == NULL)
    {
        fprintf(stderr,"Unable to open the adapter. %s is not supported by Pcap\n", dev);
    }
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
    if(pcap_sendpacket(fp,(const u_char*)&mh,42) != 0)
    {
        fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(fp));
    }
}

int main(int argc,char *argv[])
{
    if(argc != 6)
    {
        printf("not enough argument!\n");
        printf("EX : DEVICE SENDER_IP SENDER_MAC TARGET_IP TARGET_MAC\n");
        return 1;
    }
    char *dev = argv[1];    //get device name
    arp_reply(dev,argv[2],argv[3],argv[4],argv[5]);
}
