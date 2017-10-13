#include "dns.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

extern int write_log( const char* fmt, ... );

int dns_write_domain( char* data, int size, char* domain, int* space )
{
    char* pdata;
    char* pdomain, *p;
    unsigned char *blen;
    int seclen;
    int left;
    
    left = size;
    if( strlen( domain ) > MAX_DOMAIN )
    {
        write_log( "[ERR] write domain failed, domain name too large." );
        return -1;
    }
    
    pdata = data;
    pdomain = domain;
    
    while( 1 )
    {
        if( pdomain[0] == 0 )
            break;
        
        p = strchr( pdomain, '.' );
        if( p )
        {
            seclen = p - pdomain;
            if( left <= seclen + 1 )
            {
                write_log( "[ERR] write domain failed, space not enough." );
                return 1;
            }
            
            blen = (unsigned char*)pdata;
            *blen = seclen;
            memcpy( pdata+1, pdomain, seclen );
            left -= ( seclen + 1 );
            pdata += ( seclen + 1 );
            pdomain = p+1;
        }
        else
        {
            seclen = strlen( pdomain );
            if( left < seclen + 2 )
            {
                write_log( "[ERR] write domain failed, space not enough." );
                return 1;
            }
            
            blen = (unsigned char*)pdata;
            *blen = seclen;
            memcpy( pdata+1, pdomain, seclen );
            blen = (unsigned char*)pdata + 1 + seclen;
            *blen = 0;
            left -= ( seclen + 2 );
            pdata += ( seclen + 2 );
            break;
        }
    }
    
    *space = size - left;
    
    return 0;
    
    
}


char* dns_ip_addr( int dns_type, char* addr )
{
    int i,len;
    static char tmp[100];
    char* out, *in;
    
    unsigned char b1,b2,b3,b4,*p;
    
    if( dns_type == DNS_TYPE_A )
    {
        p = (unsigned char*)addr;
        b1 = *p;
        
        p = (unsigned char*)addr + 1;
        b2 = *p;
        
        p = (unsigned char*)addr + 2;
        b3 = *p;
        
        p = (unsigned char*)addr + 3;
        b4 = *p;
        
        sprintf( tmp, "%d.%d.%d.%d", b1, b2, b3, b4 );
    }
    else
    {
        in = addr;
        out = tmp;
        for( i = 0; i < 8; i++ )
        {
            p = (unsigned char*)in;
            b1 = *p;
            
            p = (unsigned char*)in+1;
            b2 = *p;
            
            if( i != 7 )
                len = sprintf( out, "%02x%02x:", b1, b2 );
            else
                len = sprintf( out, "%02x%02x", b1, b2 );
            
            out += len;
            
            in += 2;
        }
    }
    
    return tmp;
    
    
}

int dns_parse_query( char* dns, int offset, int size, char* domain, int* dns_type, int* dns_class, int* space )
{
    int rc;
    int sp;
    int left;
    unsigned short val, *pval;
    
    left = size;
    
    rc = dns_parse_domain( dns, offset, domain, &sp );
    if( rc )
        return 1;
    
    left -= sp;
    offset += sp;
    
    if( left < 4 )
    {
        write_log( "[ERR] data not enough, dns data corrupted." );
        return 1;
    }
    
    pval = (unsigned short*)( dns + offset );
    val = *pval;
    val = ntohs( val );
    *dns_type = val;
    offset += 2;
    
    pval = (unsigned short*)( dns + offset );
    val = *pval;
    val = ntohs( val );
    *dns_class = val;
    offset += 2;
    
    *space = sp + 4;
    
    return 0;
}

int dns_parse_resource_record( char* dns, int offset, int size, char* domain, char* address, int* dns_type, int* dns_class, int* ttl, int* space )
{
    int sp, sp_domain;
    int left;
    unsigned short val, *pval;
    unsigned int   ival, *pival;
    int dtype, dclass;
    int len;
    
    sp = 0;
    left = size;
    
    if( left < 12 )
    {
        write_log( "[ERR] data not long enough for dns resource record, dns data corrupted." );
        return 1;
    }
    
    dns_parse_domain( dns, offset, domain, &sp_domain );
    offset += sp_domain;
    left -= sp_domain;
    sp += sp_domain;
    
    //type
    pval = (unsigned short*)(dns+offset);
    val = *pval;
    dtype = ntohs( val );
    *dns_type = dtype;
    offset += 2;
    left -= 2;
    sp += 2;
    
    //class
    pval = (unsigned short*)(dns+offset);
    val = *pval;
    dclass = ntohs( val );
    *dns_class = dclass;
    offset += 2;
    left -= 2;
    sp += 2;
    
    //ttl
    pival = (unsigned int*)(dns+offset);
    ival  = *pival;
    ival  = ntohl( ival );
    *ttl = ival;
    offset += 4;
    left -= 4;
    sp += 4;
    
    //data len
    pval = (unsigned short*)(dns+offset);
    val  = *pval;
    len  = ntohs( val );
    offset += 2;
    left -= 2;
    sp+= (len+2);
    
    if( left < len )
    {
        write_log( "[WRN] data not long enough for resource record, dns data corrupted." );
        return 1;
    }
    
    switch( dtype )
    {
        case DNS_TYPE_A:
            if( len != 4 )
            {
                write_log( "[WRN] address length is not 4 for ipv4 address, dns data corrupted." );
                return 1;
            }
            memcpy( address, (dns+offset), 4 );
            offset += 4;
            left -= 4;
            break;
         
         case DNS_TYPE_AAAA:
            if( len != 16 )
            {
                write_log( "[WRN] address length is not 16 for ipv6 address, dns data corrupted." );
                return 1;
            }
            memcpy( address, (dns+offset), 16 );
            offset += 16;
            left -= 16;
            break;
        
        case DNS_TYPE_CNAME:
            if( dns_parse_domain( dns, offset, address, &sp_domain ) )
            {
                write_log( "[WRN] parse domain failed, dns data corrupted." );
                return 1;              
            }
            
            offset += len;
            left -= len;
            break;
        
        
        default:
            if( len > MAX_DOMAIN )
            {
                write_log( "[WRN] resource record address to large, dns data corrupted." );
                return 1;
            }
            
            offset += len;
            left -= len;
    }
    
    *space = sp;
    
    return 0;
    
}


char* dns_type_name( int dns_type )
{
    switch( dns_type )
    {
        case DNS_TYPE_A:
            return "ipv4";
        
        case DNS_TYPE_CNAME:
            return "cname";
        
        case DNS_TYPE_AAAA:
            return "ipv6";
        
        default:
            return "unknow";
    }
}

int dns_parse_domain( char* dns, int offset, char* domain, int* space )
{
    unsigned char val, *pval;
    unsigned short len;

    int sp = 0;
    int domain_len = 0;
    int org = 1;
    
    while( 1 )
    {
        pval = (unsigned char*)(dns + offset);
        val = *pval;
        
        if( val == 0 )
        {
            domain[domain_len-1] = 0;
            domain_len--;
            if( org )
                sp++;
            break;
        }
        else if( val <= 63 )
        {
            memcpy( domain + domain_len, dns + offset + 1, val );
            domain_len += val;
            domain[domain_len] = '.';
            domain_len ++;
            
            offset += (val+1);
            
            if( org )
                sp += (val+1 );
        }
        else
        {
            len = *(unsigned short*)( dns + offset );
            len = ntohs( len );
            len = len & ( ~0xc000 );
            
            if( org )
                sp += 2;
            
            org = 0;
            offset = len;
        }
    }
    
    *space = sp;
    
    return 0;
    
    
    
}


