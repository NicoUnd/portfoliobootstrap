#include <stdio.h>
#include "pcolparse.h"

FILE *log_file_ptr;

void fill_IP_header(IP_Header* ip_header_ptr, buffer[6 * 4]) {
    ip_header_ptr->version = buffer[0] >> 4;
    ip_header_ptr->IHL = buffer[0];
    ip_header_ptr->type_of_service = buffer[1];
    ip_header_ptr->total_length = buffer[2] << 8 | buffer[3];
    ip_header_ptr->identification = buffer[4] << 8 | buffer[5];
    ip_header_ptr->flags = buffer[6] >> 5;
    ip_header_ptr->fragment_offset = buffer[6] << 8 | buffer[7];
    ip_header_ptr->time_to_live = buffer[8];
    ip_header_ptr->protocol = buffer[9];
    ip_header_ptr->header_checksum = buffer[10] << 8 | buffer[11];
    ip_header_ptr->source_address = buffer[12] << 24 | buffer[13] << 16 | buffer[14] << 8 | buffer[15];
    ip_header_ptr->destination_address = buffer[16] << 24 | buffer[7] << 16 | buffer[18] << 8 | buffer[19];
    ip_header_ptr->options = buffer[20] << 16 | buffer[21] << 8 | buffer[22];
}

void fill_TCP_header(TCP_Header* tcp_header_ptr, buffer[6 * 4]) {
    tcp_header_ptr->source_port = buffer[0] << 8 | buffer[1];
    tcp_header_ptr->destination_port = buffer[2] << 8 | buffer[3];
    tcp_header_ptr->sequence_number = buffer[4] << 24 | buffer[5] << 16 | buffer[6] << 8 | buffer[7];
    tcp_header_ptr->acknowledgment_number = buffer[8] << 24 | buffer[9] << 16 | buffer[10] << 8 | buffer[11];
    tcp_header_ptr->data_offset = buffer[12] >> 4;
    tcp_header_ptr->reserved = buffer[12] << 8 | buffer[13];
    tcp_header_ptr->window = buffer[14] << 8 | buffer[15];
    tcp_header_ptr->checksum = buffer[16] << 8 | buffer[17];
    tcp_header_ptr->urgent_pointer = buffer[18] << 8 | buffer[19];
    tcp_header_ptr->options = buffer[20] << 16 | buffer[21] << 8 | buffer[22];
}