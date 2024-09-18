#include <net/ethernet.h>
#include <netinet/ip.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

// void packet_handler( u_char* args, const struct pcap_pkthdr* pack_hdr,
//                      const u_char* packet )
// {
//     printf( "Packet captured of length: %d\n", pack_hdr->len );

//     printf( "Grabbed packet of length %d\n", pack_hdr->len );
//     printf( "Recieved at ..... %s\n",
//             ctime( ( const time_t* ) &pack_hdr->ts.tv_sec ) );
//     printf( "Ethernet address length is %d\n", ETHER_HDR_LEN );

//     struct ether_header* ether_ptr;
//     ether_ptr = ( struct ether_header* ) packet;

//     if ( ntohs( ether_ptr->ether_type ) == ETHERTYPE_IP )
//     {
//         printf( "Ethernet type hex:%x dec:%d is an IP packet\n",
//                 ntohs( ether_ptr->ether_type ),
//                 ntohs( ether_ptr->ether_type ) );
//     }
//     else if ( ntohs( ether_ptr->ether_type ) == ETHERTYPE_ARP )
//     {
//         printf( "Ethernet type hex:%x dec:%d is an ARP packet\n",
//                 ntohs( ether_ptr->ether_type ),
//                 ntohs( ether_ptr->ether_type ) );
//     }
//     else
//     {
//         printf( "Ethernet type %x not IP", ntohs( ether_ptr->ether_type ) );
//         exit( 1 );
//     }

//     int32_t i;
//     u_char* ptr;

//     ptr = ether_ptr->ether_dhost;
//     i   = ETHER_ADDR_LEN;
//     printf( " Destination Address:  " );
//     do
//     {
//         printf( "%s%x", ( i == ETHER_ADDR_LEN ) ? " " : ":", *ptr++ );
//     } while ( --i > 0 );
//     printf( "\n" );

//     ptr = ether_ptr->ether_shost;
//     i   = ETHER_ADDR_LEN;
//     printf( " Source Address:  " );
//     do
//     {
//         printf( "%s%x", ( i == ETHER_ADDR_LEN ) ? " " : ":", *ptr++ );
//     } while ( --i > 0 );
//     printf( "\n" );
// }

// int main( int argc, char* argv[] )
//{
//     char       errbuf[ PCAP_ERRBUF_SIZE ];
//     pcap_if_t* devices = NULL;
//
//     bpf_u_int32 maskp; /* subnet mask */
//     bpf_u_int32 netp;  /* ip          */
//
//     int ret = pcap_findalldevs( &devices, errbuf );
//     if ( ret != 0 )
//     {
//         fprintf( stderr, "Couldn't find default device: %s\n", errbuf );
//         return ( 2 );
//     }
//
//     pcap_if_t* dev = devices;
//     if ( pcap_lookupnet( dev->name, &netp, &maskp, errbuf ) == -1 )
//     {
//         fprintf( stderr, "Can't get netmask for device %s\n", dev->name );
//         netp  = 0;
//         maskp = 0;
//     }
//
//     printf( "DEV : %s\n", dev->name );
//
//     pcap_t* handle;
//     handle = pcap_open_live( dev->name, BUFSIZ, 1, 0, errbuf );
//     if ( handle == NULL )
//     {
//         fprintf( stderr, "Couldn't open device %s: %s\n", dev->name, errbuf
//         ); return ( 2 );
//     }
//
//     const u_char*      packet;
//     struct pcap_pkthdr pack_hdr;
//     packet = pcap_next( handle, &pack_hdr );
//     if ( packet == NULL )
//     {
//         printf( "No packet for you today\n" );
//         return ( 2 );
//     }
//
//     // pcap_loop( handle, 0, packet_handler, NULL );
//
//     printf( "Grabbed packet of length %d\n", pack_hdr.len );
//     printf( "Recieved at ..... %s\n",
//             ctime( ( const time_t* ) &pack_hdr.ts.tv_sec ) );
//     printf( "Ethernet address length is %d\n", ETHER_HDR_LEN );
//
//     struct ether_header* ether_ptr;
//     ether_ptr = ( struct ether_header* ) packet;
//
//     if ( ntohs( ether_ptr->ether_type ) == ETHERTYPE_IP )
//     {
//         printf( "Ethernet type hex:%x dec:%d is an IP packet\n",
//                 ntohs( ether_ptr->ether_type ),
//                 ntohs( ether_ptr->ether_type ) );
//
//         // Skip the Ethernet header (14 bytes)
//         const u_char* ip_header = packet + sizeof( struct ether_header );
//         struct ip*    ip_ptr    = ( struct ip* ) ip_header;
//
//         // Extract and print IP addresses
//         printf( "Source IP: %s\n", inet_ntoa( ip_ptr->ip_src ) );
//         printf( "Destination IP: %s\n", inet_ntoa( ip_ptr->ip_dst ) );
//     }
//     else if ( ntohs( ether_ptr->ether_type ) == ETHERTYPE_ARP )
//     {
//         printf( "Ethernet type hex:%x dec:%d is an ARP packet\n",
//                 ntohs( ether_ptr->ether_type ),
//                 ntohs( ether_ptr->ether_type ) );
//     }
//     else
//     {
//         printf( "Ethernet type %x not IP", ntohs( ether_ptr->ether_type ) );
//         exit( 1 );
//     }
//
//     int32_t i;
//     u_char* ptr;
//
//     ptr = ether_ptr->ether_dhost;
//     i   = ETHER_ADDR_LEN;
//     printf( " Destination Address:  " );
//     do
//     {
//         printf( "%s%x", ( i == ETHER_ADDR_LEN ) ? " " : ":", *ptr++ );
//     } while ( --i > 0 );
//     printf( "\n" );
//
//     ptr = ether_ptr->ether_shost;
//     i   = ETHER_ADDR_LEN;
//     printf( " Source Address:  " );
//     do
//     {
//         printf( "%s%x", ( i == ETHER_ADDR_LEN ) ? " " : ":", *ptr++ );
//     } while ( --i > 0 );
//     printf( "\n" );
//
//     pcap_freealldevs( devices );
//     return ( 0 );
// }

/*
 * Generic per-packet information, as supplied by libpcap.
 *
 * The time stamp can and should be a "struct timeval", regardless of
 * whether your system supports 32-bit tv_sec in "struct timeval",
 * 64-bit tv_sec in "struct timeval", or both if it supports both 32-bit
 * and 64-bit applications.  The on-disk format of savefiles uses 32-bit
 * tv_sec (and tv_usec); this structure is irrelevant to that.  32-bit
 * and 64-bit versions of libpcap, even if they're on the same platform,
 * should supply the appropriate version of "struct timeval", even if
 * that's not what the underlying packet capture mechanism supplies.
 */
//struct pcap_pkthdr {
//	struct timeval ts;	/* time stamp */
//	bpf_u_int32 caplen;	/* length of portion present */
//	bpf_u_int32 len;	/* length of this packet (off wire) */
//#ifdef __APPLE__
//	char comment[256];
//#endif
//};

//typedef struct  ether_header {
//	u_char  ether_dhost[ETHER_ADDR_LEN];
//	u_char  ether_shost[ETHER_ADDR_LEN];
//	u_short ether_type;
//} ether_header_t;

void callMeBaby( u_char* args, const struct pcap_pkthdr* packHdr,
                 const u_char* packet )
{
    struct ether_header* ether_ptr;
    ether_ptr = ( struct ether_header* ) packet;

    static int count = 1;
    if( ! ether_ptr-> )
    {

    }

    fprintf( stdout, "%d, ", count );

    if ( count == 4 )
    {
        fprintf( stdout, "Come on baby sayyy you love me!!! " );
    }

    if ( count == 7 )
    {
        fprintf( stdout, "Tiiimmmeesss!! " );
        count = 0;
    }

    fflush( stdout );
    count++;
}

int main( int argc, char* argv[] )
{
    if ( argc != 2 )
    {
        fprintf( stdout, "Usage: %s numpackets\n", argv[ 0 ] );
        return 0;
    }

    char       errbuf[ PCAP_ERRBUF_SIZE ];
    pcap_if_t* dev = NULL;

    bpf_u_int32 maskp; /* subnet mask */
    bpf_u_int32 netp;  /* ip          */

    int ret = pcap_findalldevs( &dev, errbuf );
    if ( ret != 0 )
    {
        fprintf( stderr, "Couldn't find default device: %s\n", errbuf );
        return ( 2 );
    }

    if ( pcap_lookupnet( dev->name, &netp, &maskp, errbuf ) == -1 )
    {
        fprintf( stderr, "Can't get netmask for device %s\n", dev->name );
        fprintf( stderr, "%s\n", errbuf );
        netp  = 0;
        maskp = 0;
        exit( 1 );
    }

    printf( "DEV : %s\n", dev->name );

    pcap_t* handle;
    handle = pcap_open_live( dev->name, BUFSIZ, 1, 0, errbuf );
    if ( handle == NULL )
    {
        printf( "pcap_open_live(): %s\n", errbuf );
        fprintf( stderr, "Couldn't open device %s: %s\n", dev->name, errbuf );
        return ( 2 );
    }

    pcap_loop( handle, 0, callMeBaby, NULL );

    fprintf( stdout, "\nDone processing packets... wheew!\n" );

    pcap_freealldevs( dev );
    return ( 0 );
}
