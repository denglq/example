#include <stdio.h>
#include <stdint.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "ofpi_in.h"
#include "ofpi_proxy.h"
#include "ofpi_log.h"


static struct protect_ip_head *nginx_nat_map;
static struct conf_info_list *conf_info_head;//tmp list head for store conf seg info 
static struct server_info_list *server_info_head;//tmp list head for store server seg info


static inline uint32_t ecmp_hash_h(uint32_t h_ip)
{
	uint32_t hash;

	hash = (h_ip & 0x1fffffff)| ((h_ip & 0xe0000000)>>3);

	return hash;
}

#define ASCIILINESZ 1024
static char * str_strip(const char * s)
{
	static char l[ASCIILINESZ+1];
	char * last ;

	if (s==NULL) return NULL ;

	while (isspace((int)*s) && *s){
		s++;
	}
	memset(l, 0, ASCIILINESZ+1);
	strcpy(l, s);
	last = l + strlen(l);
	while (last > l) {
		if (!isspace((int)*(last-1)))
			break ;
		last--;
	}
	*last = (char)0;
	return (char*)l ;
}

#if 1
static void nginx_nat_map_dump(void)
{
	int i;
	for(i=0;i<_64M;i++){
		struct protect_ip_s *tmp = NULL;
		OFP_SLIST_FOREACH(tmp,&(nginx_nat_map[i]),next){
			if(tmp->up_server_ip){
				printf("server_ip:%d  include:",tmp->up_server_ip);
				struct proxy_tuple_s *t_tmp = NULL;
				OFP_SLIST_FOREACH(t_tmp,tmp->tcp_tuple_head,next){
					printf("\n\t\tup_server_ip:%d,up_server_port:%d,listen_ip:%d,listen_port:%d,protocol:%d",
							t_tmp->up_server_ip,t_tmp->up_server_port,
							t_tmp->down_server_ip,htons(t_tmp->down_server_port),t_tmp->protocol);	
				}
				printf("\n");

			}
		}
	}
	return;
}
#endif

static char *extract_domain_name(char *line)
{
	int len = 0;
	static char buf[ASCIILINESZ];
	
	memset(buf,0,ASCIILINESZ);
	strcpy(buf,line);
	char *p = strchr(buf,(int)' ');
	while(isspace(*p)){
		p++;
	}
	if(!strncmp(p,"http",4)){
		p += 4;
		while(!isalpha(*p)){
			p++;
		}
	}

	len = strlen(p);
	while(!isalpha(p[len-1])){
		len--;
	}
	p[len] = '\0';

	return p;
}

static int save_domain_name(char *line, char *buf)
{
	char * p = extract_domain_name(line);
	if(p == NULL){
		return -1;
	}
	//	printf("after extract domain name:%s\n",p);


	if(sscanf(p,"%s",buf) != 1){
		printf("Failed to save_domain_name at %s:%d\n",__FUNCTION__,__LINE__);
		return -1;
	}

	return 0;
}

static int up_info_insert(char *line,char *domain_name)
{
	char buf[1024] = {0};
	char ip[100] = {0};
	uint32_t nip = 0;
	uint16_t port = 0;
//	uint32_t hash = 0;
	uint32_t len = strlen(domain_name);

	char *p = strcpy(buf,line);
	while(!isdigit(*p))
	{
		p++;
	}
//	printf("p->%s\n",p);
	if(sscanf(p,"%[^:]:%d",ip,(int *)&port) != 2){
		return -1;
	}
//	printf("ip:%s   port:%u\n",ip,port);
	nip = inet_addr(ip);
//	hash = ecmp_hash_h(nip) & (_64M-1);
/* for debug */
//	printf("upstream ip:%s,port:%d,hash:%d,domain_name:%s\n",ip,port,hash,domain_name);
	/* save into conf_info_list first */
	struct conf_info_s *tmp = (struct conf_info_s *)malloc(sizeof(struct conf_info_s));
	memset(tmp,0,sizeof(struct conf_info_s));
	tmp->server_ip = nip;
	tmp->server_port = htons(port);
	strncpy(tmp->domain_name,domain_name,len);
	OFP_SLIST_INSERT_HEAD(conf_info_head,tmp,next);


	return 0;
}

static int upstream_parse(FILE *fp,char *upstream_line)
{
	char buf[1024] = {0};
	char up_domain_name[1024] = {0};
	char *line = NULL;

	if(save_domain_name(upstream_line,up_domain_name) < 0){
		return -1;
	}
	while(fgets(buf,sizeof(buf),fp) != NULL){
		line = str_strip(buf);
		if(line[0] == '#'){
			continue;
		}
		if(!strncmp(line,"server",6)){
			if(up_info_insert(line,up_domain_name) < 0){
				return -1;
			}
		}
		if(strchr(line,'}')){
			break;
		}
	}
	
	return 0;
}

static int save_listen_info(char *line,char *ip,uint16_t *port){
	char *p = strchr(line,' ');
	if(p == NULL){
		return -1;
	}
	while(!isdigit(*p)){
		p++;
	}

	if(sscanf(p,"%[^:]:%d",ip,(int *)port) != 2){
		printf("Failed to save_listen_info at %s:%d\n",__FUNCTION__,__LINE__);
		return -1;
	}

	return 0;
}


static void server_info_insert(char *proxy_domain_name,char *ip,uint16_t port)
{
	uint32_t nip = inet_addr(ip);
	uint16_t nport = htons(port);
	int len;
	len = strlen(proxy_domain_name);

	struct server_info_s *tmp = (struct server_info_s *)malloc(sizeof(struct server_info_s));
	memset(tmp,0,sizeof(struct server_info_s));
	tmp->listen_ip = nip;
	tmp->listen_port = nport;
	strncpy(tmp->domain_name,proxy_domain_name,len);
	OFP_SLIST_INSERT_HEAD(server_info_head,tmp,next);

	return;
}


static int server_parse(FILE *fp)
{
	char buf[1024] = {0};
	char proxy_domain_name[1024] = {0};
	char ip[100] = {0};
	uint16_t port = 0;
	int info_saved = 0;
	int location_block = 0;
	char *line = NULL;

	if(!fp){
		return -1;
	}
	while(fgets(buf,sizeof(buf),fp) != NULL){
		line = str_strip(buf);
		if(line[0] == '#'){
			continue;
		}
		if(!strncmp(line,"location",8)){
			location_block += 1;
			continue;
		}
		if(strchr(line,'}')){
			if(location_block){
				location_block--;
			}
			else{
				server_info_insert(proxy_domain_name,ip,port);
				break;
			}
			continue;
		}
		if(!strncmp(line,"listen",6) && (!info_saved)){
			//only assign while port = 0;
			if(save_listen_info(line,ip,&port) < 0){
				return -1;
			}
			info_saved = 1;
			continue;
		}
		/*multiple proxy_pass?*/
		if(!strncmp(line,"proxy_pass",10) && location_block){
			if(save_domain_name(line,proxy_domain_name) < 0){
				return -1;
			}
			continue;
		}
	}


	return 0;
}

static void chunk_info_merge(void)
{
	struct conf_info_s *c_tmp = NULL;
	struct server_info_s *s_tmp = NULL;
	int len = 0;

	OFP_SLIST_FOREACH(s_tmp,server_info_head,next){
		OFP_SLIST_FOREACH(c_tmp,conf_info_head,next){
			len = strlen(c_tmp->domain_name);
			if(!strncmp(s_tmp->domain_name,c_tmp->domain_name,len)){
				c_tmp->listen_ip = s_tmp->listen_ip;
				c_tmp->listen_port = s_tmp->listen_port;
			}
		}
	}

#if 1
	struct conf_info_s *tmp = NULL;
	OFP_SLIST_FOREACH(tmp,conf_info_head,next){
		printf("server_ip:%d,server_port:%d,domain_name:%s,listen_ip:%d,listen_port:%d\n"
				,tmp->server_ip,ntohs(tmp->server_port),tmp->domain_name,tmp->listen_ip,ntohs(tmp->listen_port));
	}
#endif
		
	return;
}


static int nginx_conf_parse(char * file_name)
{
	FILE *fp = NULL;
	char buf[ASCIILINESZ+1] = {0};
	char *line = NULL;
	const char *name = file_name;

#if 1
	char ip[100] = {0};
	uint32_t port = 0;
	sscanf("192.168.1.5:80","%[^:]:%d",ip,&port);
	printf("conf_parse:ip:%s,port:%d\n",ip,port);
#endif

	fp = fopen(name,"r");
	if(!fp){
		printf("Failed to open nginx configure file ! %s:%s\n",__FILE__,__FUNCTION__);
		return -1;
	}
	while(fgets(buf,sizeof(buf),fp) != NULL){
		line = str_strip(buf);
		if(line[0] == '#'){
			continue;
		}
		if(!strncmp(line,"server",6) && strchr(line,'{')){
			if(server_parse(fp) < 0){
				printf("Failed when do server_parse at:%s:%d\n",__FUNCTION__,__LINE__);
				return -1;
			}
			continue;
		}
		if(!strncmp(line,"upstream",8) && strchr(line,'{')){
			if(upstream_parse(fp,line) < 0){
				printf("Failed when do server_parse at:%s:%d\n",__FUNCTION__,__LINE__);
				return -1;
			}
			continue;
		}
	}
	fclose(fp);
	chunk_info_merge();
	return 0;
}

static struct protect_ip_s * protect_ip_node_get(uint32_t ip)
{
	uint32_t hash = 0;
	hash = ecmp_hash_h(ip) & (NAT_MAP_MASK);
	struct protect_ip_s *tmp = NULL;

	OFP_SLIST_FOREACH(tmp,&(nginx_nat_map[hash]),next){
		if(tmp->up_server_ip == ip){
			return tmp;
		}
	}

	return NULL;
}

static struct proxy_tuple_s *proxy_tuple_node_get(struct proxy_tuple_head *head,uint16_t port)
{
	struct proxy_tuple_s * t_tmp = NULL;	
	OFP_SLIST_FOREACH(t_tmp,head,next){
		if(t_tmp->up_server_port == port){
			return t_tmp;
		}
	}
	return NULL;
}


static void proxy_tuple_node_add(struct conf_info_s *data,struct proxy_tuple_head *head)
{
	struct proxy_tuple_s * t_tmp = NULL;
	t_tmp = (struct proxy_tuple_s *)malloc(sizeof(struct proxy_tuple_s));
	if(t_tmp == NULL){
		printf("malloc error at %s:%s\n",__FILE__,__FUNCTION__);
	}
	memset(t_tmp,0,sizeof(struct proxy_tuple_s));
	t_tmp->up_server_ip = data->server_ip;
	t_tmp->up_server_port = data->server_port;
	t_tmp->down_server_ip = data->listen_ip;
	t_tmp->down_server_port = data->listen_port;
	t_tmp->protocol = OFP_IPPROTO_TCP;
	OFP_SLIST_INSERT_HEAD(head,t_tmp,next);

	return;
}

proxy_tuple_t *find_proxy_node(uint32_t ip,uint8_t proto,uint16_t dport)
{
  	struct protect_ip_s *s_tmp = protect_ip_node_get(ip);
	/* proto : distinguish tcp udp icmp ... */
	if(s_tmp && proto){
		struct proxy_tuple_s *t_tmp = proxy_tuple_node_get(s_tmp->tcp_tuple_head,dport);
		if(t_tmp){
			return t_tmp;
		}
	}
	return NULL;
}


static void nginx_nat_map_init(void)
{
	struct conf_info_s *c_tmp = NULL;
	uint32_t hash = 0;

	OFP_SLIST_FOREACH(c_tmp,conf_info_head,next){
		struct protect_ip_s *s_tmp = NULL;
		s_tmp = protect_ip_node_get(c_tmp->server_ip);
		if(s_tmp){
			struct proxy_tuple_s * t_tmp = NULL;
			t_tmp =	proxy_tuple_node_get(s_tmp->tcp_tuple_head,c_tmp->server_port); 
			if(t_tmp == NULL){
				proxy_tuple_node_add(c_tmp,s_tmp->tcp_tuple_head);
			}
		}
		else{
			hash = ecmp_hash_h(c_tmp->server_ip) & (NAT_MAP_MASK);
			s_tmp = (struct protect_ip_s *)malloc(sizeof(struct protect_ip_s));	
			memset(s_tmp,0,sizeof(struct protect_ip_s));
			s_tmp->up_server_ip = c_tmp->server_ip;
			OFP_SLIST_INSERT_HEAD(&(nginx_nat_map[hash]),s_tmp,next);
			s_tmp->tcp_tuple_head = (struct proxy_tuple_head *)malloc(sizeof(struct proxy_tuple_head));
			memset(s_tmp->tcp_tuple_head,0,sizeof(struct proxy_tuple_head));
			proxy_tuple_node_add(c_tmp,s_tmp->tcp_tuple_head);
		}
	}


	return;
}

static void tmp_list_destroy(void)
{
	struct conf_info_s *tmp = OFP_SLIST_FIRST(conf_info_head);
	struct conf_info_s *del;
	for(;tmp!=NULL;){
		del = tmp;
		tmp = OFP_SLIST_NEXT(tmp,next);
		free(del);
	}
	free(conf_info_head);
	struct server_info_s *s_tmp = OFP_SLIST_FIRST(server_info_head);
	struct server_info_s *s_del;
	for(;s_tmp!=NULL;){
		s_del = s_tmp;
		s_tmp = OFP_SLIST_NEXT(s_tmp,next);
		free(s_del);
	}
	free(server_info_head);
	return;
}

static char *nginx_conf_get(void)
{
	static char line[1024] = {0};

	FILE *fp = fopen(PROXY_CONF,"r");
	if(!fp){
		printf("Failed to open PROXY_CONF! %s:%s\n",__FILE__,__FUNCTION__);
		return NULL;
	}
	while(fgets(line,sizeof(line),fp) != NULL){
		char *tmp = NULL;
		if(line[0] == '#'){
			continue;
		}
		if(!strncmp(line,"nginx_conf_file",15)){
			tmp = strchr(line,'=');
			if(tmp){
				fclose(fp);
				return ++tmp;
			}
		}
	}
	fclose(fp);
	return NULL;
}

int nginx_proxy_init(void)
{
	char *conf_name = str_strip(nginx_conf_get());
	if(conf_name == NULL){
		printf("Failed to get nginx_conf name at %s:%s\n",__FILE__,__FUNCTION__);
		return -1;
	}
	
	nginx_nat_map = (struct protect_ip_head *)malloc(_64M*sizeof(struct protect_ip_head));
	if(nginx_nat_map == NULL){
		OFP_ERR("Failed to init ngxin_nat_map.");
		return -1;
	}	
	memset(nginx_nat_map,0,_64M*sizeof(struct protect_ip_head));

	conf_info_head = (struct conf_info_list *)malloc(sizeof(struct conf_info_list));
	OFP_SLIST_INIT(conf_info_head);
	server_info_head = (struct server_info_list *)malloc(sizeof(struct server_info_list));
	OFP_SLIST_INIT(server_info_head);

	if(nginx_conf_parse(conf_name) < 0){
		return -1;	
	}
	nginx_nat_map_init();
	tmp_list_destroy();

/*for debug*/
	nginx_nat_map_dump();


	return 0;
}
