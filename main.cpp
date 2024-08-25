#include <cstdio>
#include <cstdlib>
#include <pcap.h>
#include <stdio.h>

int main( int argc, char* argv[] )
{
    char       errbuf[ PCAP_ERRBUF_SIZE ];
    pcap_if_t* devices = nullptr;

    bpf_u_int32 maskp; /* The netmask of our sniffing device */
    bpf_u_int32 netp;  /* The IP of our sniffing device */

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

    /* get the network address in a human readable form */
    struct in_addr addr;
    addr.s_addr = netp;
    char* net   = inet_ntoa( addr );

    if ( net == NULL )
    {
        perror( "inet_ntoa" );
        exit( 1 );
    }

    printf( "Net : %s\n", net );

    addr.s_addr = maskp;
    char* mask  = inet_ntoa( addr );

    if ( mask == NULL )
    {
        perror( "inet_ntoa" );
        exit( 1 );
    }

    printf( "Mask: %s\n", mask );

    pcap_freealldevs( devices );
    return ( 0 );
}
