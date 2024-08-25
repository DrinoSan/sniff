#include <pcap.h>
#include <stdio.h>

int main( int argc, char* argv[] )
{
    char *     dev, errbuf[ PCAP_ERRBUF_SIZE ];
    pcap_if_t* devics = nullptr;

    int ok = pcap_findalldevs( &devics, errbuf );
    if ( ok != 0 )
    {
        fprintf( stderr, "Couldn't find default device: %s\n", errbuf );
        return ( 2 );
    }

    pcap_if_t* device = devics;
    while( device != nullptr )
    {
        printf( "Device: %s\n", device->name );
        device = device->next;
    }

    return ( 0 );
}
