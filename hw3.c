#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include "dns.h"


const uint8_t RECTYPE_A=1;
const uint8_t RECTYPE_NS=2;
const uint8_t RECTYPE_CNAME=5;
const uint8_t RECTYPE_SOA=6;
const uint8_t RECTYPE_PTR=12;
const uint8_t RECTYPE_AAAA=28;

typedef struct address_storage{ // addrst a; a.family; a.addr.v4; a.addr.v6
	uint8_t family;
	union{
		struct in_addr v4;
		struct in6_addr v6;
	}addr;
} addrst; 

static int debug=0;//, nameserver_flag=0;

int resolve_recur( int, char*, int, const addrst*, addrst*);


/****************************************************************************************
* Exits with status stat
****************************************************************************************/
void finish( const char* msg, int stat, int witherr)
{
	if( witherr)
		perror( msg);
	else
		printf("%s\n", msg);

	exit( stat);
}

/**************************************************************************************************
**************************************************************************************************/
void usage() {
	const char* msg = "Usage: hw3 -i domain";
	//write( STDERR_FILENO, msg, strlen( msg));
	finish("Usage: hw3 -i domain",1,0);
}

/**************************************************************************************************
* wrapper for inet_ntop that takes an address_storage struct as argument
**************************************************************************************************/
const char * as_ntop(addrst * ss, char * dst, int dstlen)
{
	/*
	 * Each of these addr assignments very likely sets addr to the same
	 * value, but that is not guaranteed by the C standard.
	 */
	void * addr;
	if (ss->family == AF_INET)
		addr = &(ss->addr.v4);
	else if (ss->family == AF_INET6)
		addr = &(ss->addr.v6);
	else
	{
		return NULL;
	}
	return inet_ntop(ss->family, addr, dst, dstlen);
}

/**************************************************************************************************
* Takes ip address <src> and stores it in network format in <dst>
**************************************************************************************************/
int as_pton(const char * src, addrst * dst){
	if (inet_pton(AF_INET,src,&(dst->addr.v4))==1){
		if(debug) printf("parsed v4 address\n");
		dst->family = AF_INET;
		return 1;
	}
	if (inet_pton(AF_INET6,src,&(dst->addr.v6))==1)
	{    
		if(debug) printf("parsed v6 address\n");
		dst->family = AF_INET6;
		return 1;
	}
	return 0;
}


/**************************************************************************************************
* constructs a DNS query message for the provided hostname
**************************************************************************************************/
int construct_query(uint8_t* query, int max_query, const char* hostname,int ipver) {
	memset(query,0,max_query);
	
	// first part of the query is a fixed size header
	struct dns_hdr *hdr = (struct dns_hdr*)query;

	// generate a random 16-bit number for session
	uint16_t query_id = (uint16_t) (random() & 0xffff);
	hdr->id = htons(query_id);
	// set header flags to request recursive query
	hdr->flags = htons(0x0000);	
	// 1 question, no answers or other records
	hdr->q_count=htons(1);

	// add the name
	int query_len = sizeof(struct dns_hdr); 
	int name_len=to_dns_style(hostname,query+query_len);
	query_len += name_len; 

	// now the query type: A for ipver=4, AAAA for ipver=6
	uint16_t *type = (uint16_t*)(query+query_len);
	if (ipver == 6)
		*type = htons(28);
	else
		*type = htons(1);
	query_len+=2;

	// finally the class: INET
	uint16_t *class = (uint16_t*)(query+query_len);
	*class = htons(1);
	query_len += 2;

	return query_len;	
}

/**************************************************************************************************
**************************************************************************************************/
char* toHex( char* dst, const uint8_t* src, size_t size)
{
	char buf[2];
	size_t i;
	dst[0] = 0;

	for( i=0; i<size; i++)
	{
		sprintf( buf, "%02x", src[i]);
		strcat( dst, buf);
	}

	return dst;

}

/**************************************************************************************************
**************************************************************************************************/
int resolve_root( int sock, char* hostname, int ipver, addrst* ans)
{
	FILE* file;
	if( !(file = fopen("root-servers.txt", "r"))) finish( "fopen() failed",1,1);
	char ipstr[256];
	int resolved = 0;
	addrst ns;

	while( fscanf( file, "%s", ipstr)!=EOF && !resolved)
	{
		if( inet_pton( AF_INET, ipstr, &(ns.addr.v4)))
			ns.family = AF_INET; 
		else if( inet_pton( AF_INET6, ipstr, &(ns.addr.v6)))
			ns.family = AF_INET6;
		else
			finish("Wrong root address",1,0);

		resolved = resolve_recur( sock, hostname, ipver, &ns, ans);
	}

	fclose( file);
	return resolved;
}

/**************************************************************************************************
**************************************************************************************************/
/*
uint8_t get_answer()
{
}
//*/
/**************************************************************************************************
* Returns 0 if couldn't get a final answer, 1 otherwise
* if returns 1 and ans->family == 0, the name doesn't exist
**************************************************************************************************/
int resolve_recur( int sock, char* hostname, int ipver, const addrst* ns, addrst* ans)
{
	int i;
	const int BUF_SIZE = 1500;
	struct sockaddr_in6 ns_addr; // to store ns info
	char recd_ns_names[20][255];// figure we're getting no more than 20 NS responses
	int recd_ns_count = 0;	
	memset( &ns_addr, 0, sizeof( struct sockaddr_in6));

	//* CREATE QUERY MESSAGE
	uint8_t query[BUF_SIZE];
	size_t querylen = construct_query( query, BUF_SIZE, hostname, ipver);
	//*/

	//* SET <ns_addr> PROPERTIES
	ns_addr.sin6_family = ns->family;
	ns_addr.sin6_port = htons( 53);
	if( ns->family == AF_INET)
		((struct sockaddr_in*)&ns_addr)->sin_addr = ns->addr.v4;
	else if( ns->family == AF_INET6)
		ns_addr.sin6_addr = ns->addr.v6;
	else
		finish( "wrong ns version", 1, 0);
	//*/

	//* SEND QUERY AND GET RESPONSE
	ssize_t recv_count = 0;
	uint8_t response[ BUF_SIZE];

	for( i=0; i<2 && !recv_count; i++)
	{
		int sent_count = sendto(	sock, query, querylen, 0, 
									(struct sockaddr*)&ns_addr, sizeof( struct sockaddr_in6));

		if( sent_count<0) finish( "sendto() failed",1,1);
		else if( sent_count < querylen) finish( "sendto() failed",1,0);

		struct timeval tout = {0, 750000}; //wait 4 seconds for response
		fd_set sock_rdset;
		FD_ZERO( &sock_rdset);	
		FD_SET( sock, &sock_rdset);

		select( sock+1, &sock_rdset, NULL, NULL, &tout);
		if( FD_ISSET( sock, &sock_rdset))
			recv_count = recv( sock, response, BUF_SIZE, 0);
		
		if( recv_count)
		{
			if( *((uint16_t*)response) != *((uint16_t*)query))
				recv_count = 0;
		}
	}

 	if( !recv_count) return 0; //RETURN if the nameserver doesn't respond
	//*/

	//* GET HEADER FIELDS
	struct dns_hdr* response_hdr = (struct dns_hdr*)response;
	uint8_t* response_ptr = response+sizeof( struct dns_hdr);

	int question_count = ntohs(response_hdr->q_count);
	int answer_count = ntohs(response_hdr->a_count);
	int auth_count = ntohs(response_hdr->auth_count);
	int other_count = ntohs(response_hdr->other_count);
	uint16_t flags = ntohs(response_hdr->flags);
	//*/

	//* CONSIDER FLAGS
	char errbuf[100];errbuf[0] = 0;
	int response_error = flags & 0xf;
	if( response_error == 1 ){
		sprintf( errbuf, "%s[%s]\n", "The name server was unable to interpret the query.", hostname);
		//write( STDERR_FILENO, errbuf, strlen(errbuf));
		return 0;
	}else if( response_error == 2){
		sprintf( errbuf, "%s[%s]\n", "Problem with the name server.",hostname);
		//write( STDERR_FILENO, errbuf, strlen(errbuf));
		return 0;
	}else if( response_error == 3){
		sprintf( errbuf, "%s[%s]\n", "Domain doesn't exist.",hostname);
		//write( STDERR_FILENO, errbuf, strlen(errbuf));
		ans->family = 0;
		return 1;
	}else if( response_error == 4){
		sprintf( errbuf, "%s[%s]\n", "Query type not supported.",hostname);
		//write( STDERR_FILENO, errbuf, strlen(errbuf));
		return 0;
	}else if( response_error == 5){
		sprintf( errbuf, "%s[%s]\n", "Server refused to perform operation.",hostname);
		//write( STDERR_FILENO, errbuf, strlen(errbuf));
		return 0;
	}
	//	write( STDERR_FILENO, errbuf, strlen(errbuf));
	//*/

	//* SKIP PAST ALL QUESTIONS
	int q;
	for(q=0;q<question_count;q++) {
		char string_name[255]; memset(string_name,0,255);
		int size=from_dns_style(response,response_ptr,string_name);
		response_ptr+=size+4;
	}
	//*/

	//... response_ptr points to after HEADER and QUESTIONS sections	

	//* AITE LETS DO THIS SH*T
	for( q=0; q<answer_count+auth_count+other_count; q++)
	{
		char string_name[255]; memset( string_name, 0, 255);	
		int namefield_len = from_dns_style( response, response_ptr, string_name);
		response_ptr+=namefield_len;
		
		//printf( "string_name = [%s]\n", string_name);
			
		//... response_ptr points to defined part of RR

		struct dns_rr* rr = (struct dns_rr*)response_ptr;
		response_ptr += sizeof( struct dns_rr);

		//... response_ptr points to value
	
		if( ntohs( rr->type) == RECTYPE_A)
		{
			if( q<answer_count)
			{//we found our answer
				ans->family = AF_INET;
				ans->addr.v4 = *((struct in_addr*)response_ptr);
				return 1;
			}
			else
			{
				addrst res_ns;
				res_ns.family = AF_INET;
				res_ns.addr.v4 = *((struct in_addr*)response_ptr);
				if( resolve_recur( sock, hostname, ipver, &res_ns, ans))
					return 1;
			}
		}
		else if( ntohs(rr->type)==RECTYPE_AAAA)
		{
			if( q<answer_count)
			{//we found our answer
				ans->family = AF_INET6;
				ans->addr.v6 = *((struct in6_addr*)response_ptr);
				return 1;
			}
			else
			{
				addrst res_ns;
				res_ns.family = AF_INET6;
				res_ns.addr.v6 = *((struct in6_addr*)response_ptr);
				if( resolve_recur( sock, hostname, ipver, &res_ns, ans))
					return 1;
			}
		}
		else if( ntohs(rr->type)==RECTYPE_CNAME)
		{
			from_dns_style(response, response_ptr, hostname);
			if( q==answer_count-1 && resolve_recur(sock, hostname, ipver, ns, ans))
				return 1;
		}
		else if( ntohs( rr->type)==RECTYPE_SOA)
		{
			ans->family = 0;
			return 1;
		}
		else if( ntohs( rr->type)==RECTYPE_NS)
			from_dns_style(response,response_ptr,recd_ns_names[recd_ns_count++]);	

		response_ptr += ntohs(rr->datalen);
	}
	//*/
	
	//if( other_count) return 0;

	for( i=0; i<recd_ns_count; i++)
	{
		addrst recd_ns_ip; memset( &recd_ns_ip, 0, sizeof( addrst));
		if( resolve_root( sock, recd_ns_names[i], 4, &recd_ns_ip) && recd_ns_ip.family)
		{
			if( resolve_recur( sock, hostname, ipver, &recd_ns_ip, ans)) return 1;
		}
	}

	
	return 0;
}

/**************************************************************************************************
**************************************************************************************************/
int main(int argc, char** argv)
{
	if(argc<2) usage();

	char* orig_hostname = 0;
	char* nameserver = 0;
	char* optString = "dn:i:";
	int opt = getopt( argc, argv, optString );

	//* GET OPTIONS AND FLAGS
	while( opt != -1 ) {
		if( opt == 'i')
			orig_hostname = optarg;
		else if( opt == 'n')
			nameserver = optarg;
		else if( opt == 'd')
			debug = 1;
		else
			usage();

		opt = getopt( argc, argv, optString );
	}

	if (!orig_hostname) usage();
	//*/

	//* CREATE SOCKET
	int sock = socket(AF_INET6, SOCK_DGRAM, 0);
	if( (sock = socket(AF_INET6, SOCK_DGRAM, 0))<0) finish( "socket() failed", 1,1);
	//*/

	//* DO IT!
	char hostname[256];
	strcpy( hostname, orig_hostname);

	char buf[256];
	addrst ans4, ans6;
	memset( &ans4, 0, sizeof( addrst));
	memset( &ans6, 0, sizeof( addrst));	
	
	if( nameserver)
	{
		addrst ns;
		if( inet_pton( AF_INET, nameserver, &(ns.addr.v4))) ns.family = AF_INET;
		else if( inet_pton( AF_INET6, nameserver, &(ns.addr.v6))) ns.family = AF_INET6;
		else finish( "wrong -n option", 1, 0);
		resolve_recur( sock, hostname, 4, &ns, &ans4); strcpy( hostname, orig_hostname);
		resolve_recur( sock, hostname, 6, &ns, &ans6);		
	}
	else
	{
		resolve_root( sock, hostname, 4, &ans4); strcpy( hostname, orig_hostname);
		resolve_root( sock, hostname, 6, &ans6);
	}
	//*/
	
	//* PRINT RESULTS
	char msgv4[256];
	char msgv6[256];
	
	sprintf( msgv4, "%s IPv4 address: %s\n",
		orig_hostname, 
		ans4.family?inet_ntop(AF_INET, &(ans4.addr.v4), buf, 256):"not found.");
	sprintf( msgv6, "%s IPv6 address: %s\n",
		orig_hostname, 
		ans6.family?inet_ntop(AF_INET6, &(ans6.addr.v6), buf, 256):"not found.");
	
	write( STDOUT_FILENO, msgv4, strlen( msgv4));
	write( STDOUT_FILENO, msgv6, strlen( msgv6));
	//write( STDERR_FILENO, msgv4, strlen( msgv4));
	//write( STDERR_FILENO, msgv6, strlen( msgv6));
	//*/

	close( sock);
	return 0;

}

