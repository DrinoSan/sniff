#include <net/ethernet.h>
#include <netinet/ip.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

void callMeBaby( u_char* args, const struct pcap_pkthdr* packHdr,
                 const u_char* packet )
{
    static int count = 1;
    fprintf( stdout, "%d, ", count );
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

	 // We need to set buffer timeout to something bigger than 0
	 // With 0 we say that first we need to fill up the buffer fully and only then we would call the callback
    pcap_t* handle = pcap_open_live( dev->name, BUFSIZ, 1, 1000, errbuf );
    if ( handle == NULL )
    {
        printf( "pcap_open_live(): %s\n", errbuf );
        fprintf( stderr, "Couldn't open device %s: %s\n", dev->name, errbuf );
        return ( 2 );
    }

	 //pcap_set_immediate_mode(handle, 1);
    /* Lets try and compile the program.. non-optimized */
    struct bpf_program fp; /* hold compiled program     */
    ret = pcap_compile( handle, &fp, argv[ 1 ], 0, netp );

    if ( ret != 0 )
    {
        fprintf( stderr, "Error calling pcap_compile\n" );
        exit( 1 );
    }

    /* set the compiled program as the filter */
    if ( pcap_setfilter( handle, &fp ) == -1 )
    {
        fprintf( stderr, "Error setting filter\n" );
        exit( 1 );
    }

    fprintf( stdout, "\nBefor pcap_loop!\n" );

    pcap_loop( handle, -1, callMeBaby, NULL );

    fprintf( stdout, "\nDone processing packets... wheew!\n" );

    pcap_freealldevs( dev );
    return ( 0 );
}
