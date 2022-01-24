#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <asm/types.h>

#define NETLINK_TEST (25)
#define MAX_PAYLOAD (1024)
#define TEST_PID (100)
#define TCP 6
#define UDP 17
#define ICMP 1
#define ANY -1
#define MAX_RULE_NUM 50
#define MAX_STATU_NUM 101
#define MAX_NAT_NUM 100
#define MAX_LOG_NUM 60

typedef struct {
	char src_ip[20];
	char dst_ip[20];
	int src_port;
	int dst_port;
	char protocol;
	bool action;
	bool log;
}Rule;
Rule rules[MAX_RULE_NUM];
int rnum = 0; //rules num

typedef struct CONNECTION{
	unsigned src_ip;
	unsigned dst_ip;
	unsigned short src_port;
	unsigned short dst_port;
	unsigned char protocol;
	unsigned long t;
	struct CONNECTION *next;
}Connection;
Connection cons[MAX_STATU_NUM*100];
int cnum = 0; //connects num

typedef struct {
	unsigned nat_ip;
	unsigned short firewall_port;
	unsigned short nat_port;
}NatEntry;
NatEntry natTable[MAX_NAT_NUM];
int nnum = 0; //nat rules num

unsigned net_ip = 3232271872, net_mask = 0xffffff00, firewall_ip = 3232299136; //内网网段，内网掩码，防火墙IP

typedef struct {
	unsigned src_ip;
	unsigned dst_ip;
	unsigned short src_port;
	unsigned short dst_port;
	unsigned char protocol;
	unsigned char action;
}Log;
Log logs[MAX_LOG_NUM];
int lnum = 0;//logs num

/*----------------------------------------------------------------------------------------------------------------*/
unsigned ipstr_to_num(const char *ip_str){
	int count = 0;
	unsigned tmp = 0,ip = 0, i;
	for(i = 0; i < strlen(ip_str); i++){
		if(ip_str[i] == '.'){
			ip = ip | (tmp << (8 * (3 - count)));
			tmp = 0;
			count++;
			continue;
		}
		tmp *= 10;
		tmp += ip_str[i] - '0';
	}
	ip = ip | tmp;
	return ip;
}

char * addr_from_net(char * buff, __be32 addr){
	__u8 *p = (__u8*)&addr;
	snprintf(buff, 16, "%u.%u.%u.%u",
		(__u32)p[3], (__u32)p[2], (__u32)p[1], (__u32)p[0]);
	return buff;
}

/*----------------------------------------------------------------------------------------------------------------*/
int netlink_create_socket(void){
	//create a socket
	return socket(AF_NETLINK, SOCK_RAW, NETLINK_TEST);
}

int netlink_bind(int sock_fd){
	struct sockaddr_nl addr;
	memset(&addr, 0, sizeof(struct sockaddr_nl));
	addr.nl_family = AF_NETLINK;
	addr.nl_pid = TEST_PID;
	addr.nl_groups = 0;
	return bind(sock_fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_nl));
}

int netlink_send_message(int sock_fd, const unsigned char *message, int len,unsigned int pid, unsigned int group){
	struct nlmsghdr *nlh = NULL;
	struct sockaddr_nl dest_addr;
	struct iovec iov;
	struct msghdr msg;
	if( !message ) {
		return -1;
	}
	//create message
	nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(len));
	if( !nlh ) {
		perror("malloc");
		return -2;
	}
	nlh->nlmsg_len = NLMSG_SPACE(len);
	nlh->nlmsg_pid = TEST_PID;
	nlh->nlmsg_flags = 0;
	memcpy(NLMSG_DATA(nlh), message, len);
	iov.iov_base = (void *)nlh;
	iov.iov_len = nlh->nlmsg_len;
	memset(&dest_addr, 0, sizeof(struct sockaddr_nl));
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid = pid;
	dest_addr.nl_groups = group;
	memset(&msg, 0, sizeof(struct msghdr));
	msg.msg_name = (void *)&dest_addr;
	msg.msg_namelen = sizeof(struct sockaddr_nl);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	//send message
	if( sendmsg(sock_fd, &msg, 0) < 0 )
	{
		printf("send error!\n");
		free(nlh);
		return -3;
	}
	free(nlh);
	return 0;
}

int netlink_recv_message(int sock_fd, unsigned char *message, int *len){
	struct nlmsghdr *nlh = NULL;
	struct sockaddr_nl source_addr;
	struct iovec iov;
	struct msghdr msg;
	if( !message || !len ) {
		return -1;
	}
	//create message
	nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
	if( !nlh ) {
		perror("malloc");
		return -2;
	}
	iov.iov_base = (void *)nlh;
	iov.iov_len = NLMSG_SPACE(MAX_PAYLOAD);
	memset(&source_addr, 0, sizeof(struct sockaddr_nl));
	memset(&msg, 0, sizeof(struct msghdr));
	msg.msg_name = (void *)&source_addr;
	msg.msg_namelen = sizeof(struct sockaddr_nl);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	if ( recvmsg(sock_fd, &msg, 0) < 0 ) {
		printf("recvmsg error!\n");
		return -3;
	}
	*len = nlh->nlmsg_len - NLMSG_SPACE(0);
	memcpy(message, (unsigned char *)NLMSG_DATA(nlh), *len);
	free(nlh);
	return 0;
}

/*----------------------------------------------------------------------------------------------------------------*/
void prt_port(int port){
	if(port==-1)
		printf("     any    ");
	else
		printf("%12d", port);
}

void prt_protocol(char protocol){
	if(protocol==6)
		printf("     TCP    ");
	else if(protocol==17)
		printf("     UDP    ");
	else if(protocol==1)
		printf("    ICMP    ");
	else
		printf("  undefined ");	
}

void print_IP(unsigned long int src_ip){
	unsigned char src_i[4];
	src_i[3] = src_ip%256; src_ip /= 256;
	src_i[2] = src_ip%256; src_ip /= 256;
	src_i[1] = src_ip%256; src_ip /= 256;
	src_i[0] = src_ip%256; src_ip /= 256;
	printf("%d.%d.%d.%d", src_i[0],src_i[1],src_i[2],src_i[3]);
}

void sprint_IP(char output[], unsigned long int src_ip){
	unsigned char src_i[4];
	src_i[3] = src_ip%256; src_ip /= 256;
	src_i[2] = src_ip%256; src_ip /= 256;
	src_i[1] = src_ip%256; src_ip /= 256;
	src_i[0] = src_ip%256; src_ip /= 256;
	sprintf(output, "%d.%d.%d.%d", src_i[0],src_i[1],src_i[2],src_i[3]);
}

//将ip_range(192.168.10.0/24) 转化成网络号(192.168.10.0)存在ip中 和 掩码(255.255.255.0)存在mask中
void Convert(unsigned& ip, unsigned& mask, const char* ip_range) {
	char tmp_ip[20];
	int p = -1, count = 0;
	unsigned len = 0, tmp = 0, i;
	ip = 0, mask = 0;
	strcpy(tmp_ip, ip_range); //  24
	for (i = 0; i < strlen(tmp_ip); i++) {
		if (p != -1) {
			len *= 10;
			len += tmp_ip[i] - '0';
		}
		else if (tmp_ip[i] == '/')
			p = i;
	}
	if (p != -1) {
		tmp_ip[p] = '\0';
		mask = 0xFFFFFFFF << (32 - len);
	}
	else mask = 0xFFFFFFFF;
	for (i = 0; i < strlen(tmp_ip); i++) {
		if (tmp_ip[i] == '.') {
			ip = ip | (tmp << (8 * (3 - count)));
			tmp = 0;
			count++;
			continue;
		}
		tmp *= 10;
		tmp += tmp_ip[i] - '0';
	}
	ip = ip | tmp;
}


/*----------------------------------------------------------------------------------------------------------------*/
int SendRules(){
	int sock_fd;
	unsigned char buf[MAX_PAYLOAD];
	unsigned char msg[5000];
	int len;
	sock_fd = netlink_create_socket();
	if(sock_fd == -1) {
		printf("socket error!\n");
		return -1;
	}
	if( netlink_bind(sock_fd) < 0 ) {
		perror("bind");
		close(sock_fd);
		exit(EXIT_FAILURE);
	}
	msg[0] = 0; //表示过滤规则
	msg[1] = rnum;
	memcpy(msg + 2, rules, rnum * sizeof(Rule));
	netlink_send_message(sock_fd, (const unsigned char *)msg, rnum * sizeof(Rule) + 2, 0, 0);
	close(sock_fd);
	return 1;
}

bool AddRule(const char *src_ip, const char *dst_ip, int src_port, int dst_port, char protocol, bool action, bool log){
	if(rnum < 100){
		strcpy(rules[rnum].src_ip, src_ip);  //rnum 全局变量表示规则数目
		strcpy(rules[rnum].dst_ip, dst_ip);
		rules[rnum].src_port = src_port;
		rules[rnum].dst_port = dst_port;
		rules[rnum].protocol = protocol;
		rules[rnum].action = action;
		rules[rnum].log = log;
		rnum++;
		return true;
	}
	return false;
}

bool DelRule(int pos){
	if(pos >= rnum || pos < 0)
		return false;
	memcpy(rules + pos, rules + pos + 1, sizeof(Rule) * (rnum - pos));
	rnum--;
	return true;
}

void PrintRules(){
	printf("Rules:\n");
	printf("|----------------------------------------------------------------------------------------------|\n");
	printf("|      src_ip      |      dst_ip      |  src_port  |  dst_port  |  protocol  |  action  |  log |\n");
	printf("|----------------------------------------------------------------------------------------------|\n");
	int i=0;
	for(i = 0; i < rnum; i++){
		printf("|%18s|%18s|", rules[i].src_ip, rules[i].dst_ip);
		prt_port(rules[i].src_port);printf("|");
		prt_port(rules[i].dst_port);printf("|");
		prt_protocol(rules[i].protocol);
		printf("|%10hhu|%6hhu|\n", rules[i].action, rules[i].log);
		printf("|----------------------------------------------------------------------------------------------|\n");
	}
	return;
}

/*----------------------------------------------------------------------------------------------------------------*/
int SendNatRules(){
	int sock_fd;
	unsigned char buf[MAX_PAYLOAD];
	unsigned char msg[5000];
	int len;
	sock_fd = netlink_create_socket();
	if(sock_fd == -1) {
		printf("socket error!\n");
		return -1;
	}
	if( netlink_bind(sock_fd) < 0 ) {
		perror("bind");
		close(sock_fd);
		exit(EXIT_FAILURE);
	}
	msg[0] = 1;//表示NAT转换规则
	msg[1] = nnum;
	memcpy(msg + 2, &net_ip, sizeof(unsigned));
	memcpy(msg + 6, &net_mask, sizeof(unsigned));
	memcpy(msg + 10, &firewall_ip, sizeof(unsigned));
	memcpy(msg + 14, natTable, nnum * sizeof(NatEntry));
	netlink_send_message(sock_fd, (const unsigned char *)msg, nnum * sizeof(NatEntry) + 14, 0, 0);
	close(sock_fd);
	return 1;
}

bool AddNatRule(unsigned nat_ip, unsigned short nat_port, unsigned short firewall_port){
	if(nnum < 100){
		natTable[nnum].nat_ip = nat_ip;
		natTable[nnum].nat_port = nat_port;
		natTable[nnum].firewall_port = firewall_port;
		nnum++;
		return true;
	}
	return false;
}

bool DelNatRule(int pos){
	if(pos >= nnum || pos < 0)
		return false;
	memcpy(natTable + pos, natTable + pos + 1, sizeof(NatEntry) * (nnum - pos));
	nnum--;
	return true;
}

//unsigned net_ip = 3232271872, net_mask = 0xffffff00, firewall_ip = 3232299136; //内网网段，内网掩码，防火墙IP
void SetNat(unsigned net, unsigned mask, unsigned ip){
	firewall_ip = ip;
	net_ip = net;
	net_mask = mask;
}

void PrintNatRules(){
	printf("Nat rules:\n");
	printf("|--------------------------------------------|\n");
	printf("|      nat_ip      |  nat_port  |  fir_port  |\n");
	printf("|--------------------------------------------|\n");
	int i = 0;
	for(i = 0; i < nnum; i++){
		char buff[20], buff2[20];
		printf("|%18s|",addr_from_net(buff2, natTable[i].nat_ip));
		prt_port(natTable[i].nat_port);printf("|");
		prt_port(natTable[i].firewall_port);printf("|\n");
		printf("|--------------------------------------------|\n");
	}
	return;
}

/*----------------------------------------------------------------------------------------------------------------*/
int GetLogs(){
	int sock_fd;
	unsigned char msg[100];
	unsigned char buf[1000 * sizeof(Log)];
	int len;
	sock_fd = netlink_create_socket();
	if(sock_fd == -1) {
		printf("socket error!\n");
		return -1;
	}
	if( netlink_bind(sock_fd) < 0 ) {
		perror("bind");
		close(sock_fd);
		exit(EXIT_FAILURE);
	}
	msg[0] = 2;//表示用户程序向内核请求日志
	netlink_send_message(sock_fd, (const unsigned char *)msg, 1, 0, 0);
	if( netlink_recv_message(sock_fd, buf, &len) == 0 ) {
		printf("recvlen:%d\n",len);
		memcpy(logs, buf, len);
		lnum = len / sizeof(Log);
	}
	close(sock_fd);
	return 1;
}

void PrintLogs(){
	printf("Logs:\n");
	printf("|---------------------------------------------------------------------------------------|\n");
	printf("|      src_ip      |      dst_ip      |  src_port  |  dst_port  |  protocol  |  action  |\n");
	printf("|---------------------------------------------------------------------------------------|\n");
	int i = 0;
	for(i = 0; i < lnum; i++){
		char buff[20], buff2[20];
		printf("|%18s|%18s|", addr_from_net(buff, logs[i].src_ip), addr_from_net(buff2, logs[i].dst_ip));
		prt_port(logs[i].src_port);printf("|");
		prt_port(logs[i].dst_port);printf("|");
		prt_protocol(logs[i].protocol);
		printf("|%10hhu|\n", logs[i].action);
		printf("|---------------------------------------------------------------------------------------|\n");
	}
}

/*----------------------------------------------------------------------------------------------------------------*/
int GetConnections(){
	int sock_fd;
	unsigned char msg[100];
	unsigned char buf[101 * sizeof(Connection)];
	int len;
	sock_fd = netlink_create_socket();
	if(sock_fd == -1) {
		printf("socket error!\n");
		return -1;
	}
	if( netlink_bind(sock_fd) < 0 ) {
		perror("bind");
		close(sock_fd);
		exit(EXIT_FAILURE);
	}
	msg[0] = 3;//表示用户向内核请求状态连接表
	netlink_send_message(sock_fd, (const unsigned char *)msg, 1, 0, 0);
	if( netlink_recv_message(sock_fd, buf, &len) == 0 ) {
		printf("recvlen:%d\n",len);
		memcpy(cons, buf, len);
		cnum = len / sizeof(Connection);
	}
	close(sock_fd);
	return 1;
}

void PrintConnections(){
	printf("Connections:\n");
	printf("|----------------------------------------------------------------------------|\n");
	printf("|      src_ip      |      dst_ip      |  src_port  |  dst_port  |  protocol  |\n");
	printf("|----------------------------------------------------------------------------|\n");
	int i = 0;
	for(i = 0; i < cnum; i++){
		char buff[20], buff2[20];
		printf("|%18s|%18s|", addr_from_net(buff, cons[i].src_ip), addr_from_net(buff2, cons[i].dst_ip));
		prt_port(cons[i].src_port);printf("|");
		prt_port(cons[i].dst_port);printf("|");
		prt_protocol(cons[i].protocol);printf("|\n");
		printf("|----------------------------------------------------------------------------|\n");
	}
	
}

int main(){
	//SetNat(ipstr_to_num("192.168.142.0"), 0xffffff00, ipstr_to_num("192.168.248.1"));
	
	//AddRule("127.0.0.1", "any", -1, -1, -1, 1, 0);
	//AddRule("any", "127.0.0.1", -1, -1, -1, 1, 0);
	//AddRule("any", "192.168.0.0/16", -1, -1, -1, 1, 0);
	//AddRule("any", "any", -1, -1, 6, 1, 1);
	//AddNatRule(ipstr_to_num("192.168.142.129"), 80, 8888);
	PrintRules();
	SendRules();
	PrintNatRules();
	SendNatRules();

	//填内网的网络号 、 内网掩码 、 防火墙外网网关IP 的十进制
	SetNat(3232271872, 0xffffff00, 3232299136);//unsigned net_ip = 3232271872, net_mask = 0xffffff00, firewall_ip = 3232299136; //内网网段，内网掩码，防火墙IP



	char tmps[20], src_ip[20], dst_ip[20], nat_ip[20];
	int src_port, dst_port;
	int protocol;
	int action, log;
	unsigned short nat_port;
	unsigned short firewall_port;
	int type=5, x;
	printf("\n\t输入1：添加防火墙过滤规则\n");
	printf("\t输入2：删除防火墙过滤规则\n");
	printf("\t输入3：添加NAT转换规则\n");
	printf("\t输入4：删除NAT转换规则\n");
	printf("\t输入5：打印过滤规则\n");
	printf("\t输入6：打印日志文件\n");
	printf("\t输入7：打印状态连接表\n");
	printf("\t输入8：打印nat转化规则\n");
	printf("\t输入0：退出程序\n");
	scanf("%d", &type);
	fflush(stdin);
	while(1)
	{
		switch(type){
		case 1:
			printf("请依次输入(以空格分隔)报文的源IP、目的IP、源端口、目的端口、协议、动作（禁止/允许）、是否记录日志\n");
			scanf("%s%s%d%d%d%d%d", src_ip, dst_ip, &src_port, &dst_port, &protocol, &action, &log);
			AddRule(src_ip, dst_ip, src_port, dst_port, protocol, action, log);
			PrintRules();
			printf("\n");
			SendRules();
			break;
		case 2:
			printf("请删除过滤规则编号(从 0 开始)\n");
			scanf("%d", &x);
			DelRule(x);
			PrintRules();
			printf("\n");
			SendRules();
			break;
		case 3:
			printf("请分别输入内网IP、内网端口号、防火墙端口\n");
			scanf("%s%hu%hu", nat_ip, &nat_port, &firewall_port);
			AddNatRule(ipstr_to_num(nat_ip), nat_port, firewall_port);
			PrintNatRules();
			printf("\n");
			SendNatRules();
			break;
		case 4:
			printf("请删除nat转化规则编号(从 0 开始)\n");
			scanf("%d", &x);
			DelNatRule(x);
			PrintNatRules();
			printf("\n");
			SendNatRules();
			break;
		case 5:
			PrintRules();
			printf("\n");
			break;
		case 6:
			GetLogs();
			PrintLogs();
			printf("lnum:%d\n", lnum);
			break;
		case 7:
			GetConnections();
			PrintConnections();
			printf("cnum:%d\n", cnum);
			break;
		case 8:
			PrintNatRules();
			break;
		case 0:
			return 0;
		default:
			break;
		}
		//system("clear");
		printf("\n\t输入1：添加防火墙过滤规则\n");
		printf("\t输入2：删除防火墙过滤规则\n");
		printf("\t输入3：添加NAT转换规则\n");
		printf("\t输入4：删除NAT转换规则\n");
		printf("\t输入5：打印过滤规则\n");
		printf("\t输入6：打印日志文件\n");
		printf("\t输入7：打印状态连接表\n");
		printf("\t输入8：打印nat转化规则\n");
		printf("\t输入0：退出程序\n");
		scanf("%d", &type);

		fflush(stdin);
	}

}






















