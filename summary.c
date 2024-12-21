#include <stdio.h>
#include "pcolparse.h"

void print_IP(unsigned int IP){
  printf("%u.%u.%u.%u ", IP >> 24, IP >> 16, IP >> 8, IP);
}

int main(int argc, const char * argv[]) {
    if (argc != 2) {
        perror("Dosage: <IP_PACKET_FILE>");
        return 1;
    }

    FILE *log_file_ptr = fopen(argv[1], "r");
    unsigned char buffer[6 * 4];

    fread(buffer, 1, 6 * 4, log_file_ptr);
    IP_Header IP_header;
    fillIPHeader(&IP_header, buffer);

    fread(buffer, 1, 6 * 4, log_file_ptr);
    TCP_Header TCP_header;
    fillTCPHeader(&TCP_header, buffer);

    print_IP(IP_header.source_address);
    print_IP(IP_header.destination_address);
    printf("%u ", IP_header.IHL);
    printf("%u ", IP_header.total_length);
    printf("%u ", TCP_header.data_offset);

    unsigned int num_of_packets = 1;
    while (!feof(log_file_ptr)){
        unsigned int rest_of_file_length = IP_header.total_length - 6 * 4;
        unsigned char discard[rest_of_file_length];
        fread(discard, 1, rest_of_file_length, log_file_ptr);
        num_of_packets += 1;
    }
    printf("%u", num_of_packets);
}