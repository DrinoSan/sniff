#include <net/ethernet.h>
#include <netinet/ip.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

struct my_ip
{
    u_int8_t ip_vhl; /* header length, version */
#define IP_V( ip )  ( ( ( ip )->ip_vhl & 0xf0 ) >> 4 )
#define IP_HL( ip ) ( ( ip )->ip_vhl & 0x0f )
    u_int8_t  ip_tos;              /* type of service */
    u_int16_t ip_len;              /* total length */
    u_int16_t ip_id;               /* identification */
    u_int16_t ip_off;              /* fragment offset field */
#define IP_DF      0x4000          /* dont fragment flag */
#define IP_MF      0x2000          /* more fragments flag */
#define IP_OFFMASK 0x1fff          /* mask for fragmenting bits */
    u_int8_t       ip_ttl;         /* time to live */
    u_int8_t       ip_p;           /* protocol */
    u_int16_t      ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

u_int16_t handle_ethernet( u_char* args, const struct pcap_pkthdr* pkthdr,
                           const u_char* packet );

u_char* handle_IP( u_char* args, const struct pcap_pkthdr* pkthdr,
                   const u_char* packet );

void callMeBaby( u_char* args, const struct pcap_pkthdr* packHdr,
                 const u_char* packet )
{
    u_int16_t type = handle_ethernet( args, packHdr, packet );

    if ( type == ETHERTYPE_IP )
    { /* handle IP packet */
        handle_IP( args, packHdr, packet );
    }
    else if ( type == ETHERTYPE_ARP )
    { /* handle arp packet */
    }
    else if ( type == ETHERTYPE_REVARP )
    { /* handle reverse arp packet */
    } /* ignorw */
}

u_char* handle_IP( u_char* args, const struct pcap_pkthdr* pkthdr,
                   const u_char* packet )
{
    /* jump pass the ethernet header */
    const struct my_ip* ip;
    ip = ( struct my_ip* ) ( packet + sizeof( struct ether_header ) );

    u_int length = pkthdr->len;
		fprintf(stdout, "pkthdr->len : %d sizeof( struct ether_header ): %lu\n", length, sizeof( struct ether_header ));
    length -= sizeof( struct ether_header );


    /* check to see we have a packet of valid length */
    if ( length < sizeof( struct my_ip ) )
    {
        printf( "truncated ip %d", length );
        return NULL;
    }

    int   len;
    u_int hlen, off, version;

    len     = ntohs( ip->ip_len );
    hlen    = IP_HL( ip ); /* header length */
    version = IP_V( ip );  /* ip version */

    /* check version */
    if ( version != 4 )
    {
        fprintf( stdout, "Unknown version %d\n", version );
        return NULL;
    }

    /* check header length */
    if ( hlen < 5 )
    {
        fprintf( stdout, "bad-hlen %d \n", hlen );
    }

    /* see if we have as much packet as we should */
    if ( length < len )
        printf( "\ntruncated IP - %d bytes missing\n", len - length );

    /* Check to see if we have the first fragment */
    off = ntohs( ip->ip_off );
    if ( ( off & 0x1fff ) == 0 ) /* aka no 1's in first 13 bits */
    { /* print SOURCE DESTINATION hlen version len offset */
        fprintf( stdout, "IP: " );
        fprintf( stdout, "%s ", inet_ntoa( ip->ip_src ) );
        fprintf( stdout, "%s %d %d %d %d\n", inet_ntoa( ip->ip_dst ), hlen,
                 version, len, off );
    }

    return NULL;
}

u_int16_t handle_ethernet( u_char* args, const struct pcap_pkthdr* pkthdr,
                           const u_char* packet )
{
    struct ether_header* eptr;   // net/ethernet.h

    eptr               = ( struct ether_header* ) packet;
    u_short ether_type = ntohs( eptr->ether_type );

    fprintf( stdout, "ethernet header source: %s",
             ether_ntoa( ( const struct ether_addr* ) &eptr->ether_shost ) );
    fprintf( stdout, "ethernet header destination: %s",
             ether_ntoa( ( const struct ether_addr* ) &eptr->ether_dhost ) );

    if ( ether_type == ETHERTYPE_IP )
    {
        fprintf( stdout, "(IP)" );
    }
    else if ( ether_type == ETHERTYPE_ARP )
    {
        fprintf( stdout, "(ARP)" );
    }
    else if ( ether_type == ETHERTYPE_REVARP )
    {
        fprintf( stdout, "(RARP)" );
    }
    else
    {
        fprintf( stdout, "\n(?)\n" );
        fprintf( stdout, "EtherType: %d\n", ether_type );
    }

    fprintf( stdout, "\n" );

    return ether_type;
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

    if ( argc > 2 )
    {
        /* Lets try and compile the program.. non-optimized */
        struct bpf_program fp; /* hold compiled program     */
        ret = pcap_compile( handle, &fp, argv[ 2 ], 0, netp );

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
    }

    pcap_loop( handle, atoi( argv[ 1 ] ), callMeBaby, NULL );

    fprintf( stdout, "\nDone processing packets... wheew!\n" );

    pcap_freealldevs( dev );
    return ( 0 );
}
