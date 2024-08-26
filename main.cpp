#include <cstdio>
#include <cstdlib>
#include <net/ethernet.h>
#include <pcap.h>
#include <stdio.h>

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

int main( int argc, char* argv[] )
{
    char       errbuf[ PCAP_ERRBUF_SIZE ];
    pcap_if_t* devices = nullptr;

    bpf_u_int32 maskp; /* subnet mask */
    bpf_u_int32 netp;  /* ip          */

    int ret = pcap_findalldevs( &devices, errbuf );
    if ( ret != 0 )
    {
        fprintf( stderr, "Couldn't find default device: %s\n", errbuf );
        return ( 2 );
    }

    pcap_if_t* dev = devices;
    if ( pcap_lookupnet( dev->name, &netp, &maskp, errbuf ) == -1 )
    {
        fprintf( stderr, "Can't get netmask for device %s\n", dev->name );
        netp  = 0;
        maskp = 0;
    }

    printf( "DEV : %s\n", dev->name );

    pcap_t* handle;
    handle = pcap_open_live( dev->name, BUFSIZ, 1, 0, errbuf );
    if ( handle == NULL )
    {
        fprintf( stderr, "Couldn't open device %s: %s\n", dev->name, errbuf );
        return ( 2 );
    }

    const u_char*      packet;
    struct pcap_pkthdr pack_hdr;
    packet = pcap_next( handle, &pack_hdr );
    if ( packet == nullptr )
    {
        printf( "No packet for you today\n" );
        return ( 2 );
    }

    // pcap_loop( handle, 0, packet_handler, NULL );

    printf( "Grabbed packet of length %d\n", pack_hdr.len );
    printf( "Recieved at ..... %s\n",
            ctime( ( const time_t* ) &pack_hdr.ts.tv_sec ) );
    printf( "Ethernet address length is %d\n", ETHER_HDR_LEN );

    struct ether_header* ether_ptr;
    ether_ptr = ( struct ether_header* ) packet;

    if ( ntohs( ether_ptr->ether_type ) == ETHERTYPE_IP )
    {
        printf( "Ethernet type hex:%x dec:%d is an IP packet\n",
                ntohs( ether_ptr->ether_type ),
                ntohs( ether_ptr->ether_type ) );
    }
    else if ( ntohs( ether_ptr->ether_type ) == ETHERTYPE_ARP )
    {
        printf( "Ethernet type hex:%x dec:%d is an ARP packet\n",
                ntohs( ether_ptr->ether_type ),
                ntohs( ether_ptr->ether_type ) );
    }
    else
    {
        printf( "Ethernet type %x not IP", ntohs( ether_ptr->ether_type ) );
        exit( 1 );
    }

    int32_t i;
    u_char* ptr;

    ptr = ether_ptr->ether_dhost;
    i   = ETHER_ADDR_LEN;
    printf( " Destination Address:  " );
    do
    {
        printf( "%s%x", ( i == ETHER_ADDR_LEN ) ? " " : ":", *ptr++ );
    } while ( --i > 0 );
    printf( "\n" );

    ptr = ether_ptr->ether_shost;
    i   = ETHER_ADDR_LEN;
    printf( " Source Address:  " );
    do
    {
        printf( "%s%x", ( i == ETHER_ADDR_LEN ) ? " " : ":", *ptr++ );
    } while ( --i > 0 );
    printf( "\n" );


    pcap_freealldevs( devices );
    return ( 0 );
}
