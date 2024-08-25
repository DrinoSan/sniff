#include <pcap.h>
#include <stdio.h>

int main( int argc, char* argv[] )
{
    char *     dev, errbuf[ PCAP_ERRBUF_SIZE ];
    pcap_if_t* devices = nullptr;

    int ok = pcap_findalldevs( &devices, errbuf );
    if ( ok != 0 )
    {
        fprintf( stderr, "Couldn't find default device: %s\n", errbuf );
        return ( 2 );
    }

    pcap_if_t* device = devices;
    while( device != nullptr )
    {
        printf( "Device: %s\n", device->name );
        device = device->next;
    }

    pcap_freealldevs(devices);
    return ( 0 );
}
