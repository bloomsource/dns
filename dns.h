#ifndef _DNS_H_
#define _DNS_H_

#ifdef __cplusplus
extern "C"{
#endif


#define DNS_PORT   53
#define MAX_DOMAIN 255

#define DNS_TYPE_A      1       //ipv4
#define DNS_TYPE_CNAME  5       //cname
#define DNS_TYPE_AAAA   28      //ipv6


typedef struct{
    unsigned short id;
    unsigned short flags;
    unsigned short qry_cnt;
    unsigned short ans_cnt;
    unsigned short auth_cnt;
    unsigned short add_cnt;
}dns_hdr;


int dns_write_domain( char* data, int size, char* domain, int* space );

int dns_parse_domain( char* dns, int offset, char* domain, int* space );

int dns_parse_query( char* dns, int offset, int size, char* domain, int* dns_type, int* dns_class, int* space );

char* dns_type_name( int dns_type );

int dns_parse_resource_record( char* dns, int offset, int size, char* domain, char* address, int* dns_type, int* dns_class, int* ttl, int* space );

char* dns_ip_addr( int dns_type, char* addr );


#ifdef __cplusplus
}
#endif




#endif
