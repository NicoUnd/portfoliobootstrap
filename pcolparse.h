typedef struct IP_Header IP_Header;
struct IP_Header {
    unsigned int version: 4;
    unsigned int IHL: 4;
    unsigned int type_of_service: 8;
    unsigned int total_length: 16;
    unsigned int identification: 16;
    unsigned int flags: 3;
    unsigned int fragment_offset: 13;
    unsigned int time_to_live: 8;
    unsigned int protocol: 8;
    unsigned int header_checksum: 16;
    unsigned int source_address: 32;
    unsigned int destination_address: 32;
    unsigned int options: 24;
};
typedef struct TCP_Header TCP_Header;
struct TCP_Header {
    unsigned int source_port: 16;
    unsigned int destination_port: 16;
    unsigned int sequence_number: 32;
    unsigned int acknowledgment_number: 32;
    unsigned int data_offset: 4;
    unsigned int reserved: 12;
    unsigned int window: 16;
    unsigned int checksum: 16;
    unsigned int urgent_pointer: 16;
    unsigned int options: 24;
};