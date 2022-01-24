#include<linux/kernel.h>
#include<linux/init.h>
#include<linux/module.h>
#include<linux/version.h>
#include<linux/skbuff.h>
#include <linux/net.h>
#include<linux/netfilter.h>
#include<linux/netfilter_ipv4.h>
#include <linux/netfilter_bridge.h>
#include <linux/netdevice.h>
#include <linux/stat.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/socket.h>
#include <linux/netlink.h>
#include <net/netlink.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/udp.h>
#include <linux/string.h>
#include <linux/kdev_t.h>
#include <linux/kmod.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/in.h>
#include <linux/jiffies.h>
#include <linux/time.h>
#include <linux/timex.h>
#include <linux/timer.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include <linux/if_arp.h>
#include <linux/rtc.h>
#include <linux/if_ether.h>
#include <linux/types.h>
#include <linux/proc_fs.h>
#include <net/sock.h>
#include <net/ip.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
 
#define NETLINK_TEST (25)
#define TCP 6
#define UDP 17
#define ICMP 1
#define ANY -1
#define ICMP_PORT 30001
#define MAX_RULE_NUM 50
#define MAX_STATU_NUM 101
#define MAX_NAT_NUM 100
#define MAX_LOG_NUM 60
 
MODULE_LICENSE("GPL");
//MODULE_AUTHER("WJT");

int flag[MAX_STATU_NUM];

//规则匹配
typedef struct RULE{
	char src_ip[20], dst_ip[20];
	int src_port, dst_port;
	char protocol;
	bool action, log;
}Rule;
Rule rules[MAX_RULE_NUM];
int rnum = 0; //rules num

//状态连接表
typedef struct CONNECTION{
	unsigned src_ip;
	unsigned dst_ip;
	unsigned short src_port;
	unsigned short dst_port;
	unsigned char protocol;
	unsigned long t;
	struct CONNECTION *next;
}Connection;
Connection *cons[MAX_STATU_NUM];
Connection cons2[MAX_STATU_NUM*100];
int cnum = 0; //connect num

//nat转换表
typedef struct NATENTRY{
	unsigned nat_ip;
	unsigned short firewall_port, nat_port;
}NatEntry;
unsigned net_ip = 3232271872, net_mask = 0xffffff00, firewall_ip = 3232299136; //内网网段，内网掩码，防火墙IP

unsigned short firewall_port = 20000;
NatEntry natTable[MAX_NAT_NUM];
int nnum = 0; //nat rules num

//日志记录表
typedef struct LOG{
    unsigned src_ip;
    unsigned dst_ip;
    unsigned short src_port;
    unsigned short dst_port;
    unsigned char protocol;
    unsigned char action;
}Log;
Log logs[MAX_LOG_NUM];
int lnum = 0;//logs num

//netlink处理信息函数
void netlink_input(struct sk_buff *__skb);
//netfilter规则过滤钩子函数
unsigned int hook_func(unsigned int,struct sk_buff *,const struct net_device *,
        const struct net_device *,int(*okfn)(struct sk_buff*));
//netfilter，nat目的地址转换钩子函数
unsigned int hook_func_nat_in(unsigned int,struct sk_buff *,const struct net_device *,
        const struct net_device *,int(*okfn)(struct sk_buff*));
//netfilter，nat源地址转换钩子函数
unsigned int hook_func_nat_out(unsigned int,struct sk_buff *,const struct net_device *,
        const struct net_device *,int(*okfn)(struct sk_buff*));

dev_t devId;
struct class *cls = NULL;
struct sock *nl_sk = NULL;
struct netlink_kernel_cfg nkc = {
	.groups = 0,
	.flags = 0,
	.input = netlink_input,
	.cb_mutex = NULL,
	.bind = NULL,
	//nkc.unbind = NULL;
	.compare = NULL
};
struct nf_hook_ops input_filter = {
	.hook = (nf_hookfn *)hook_func,
	.owner = THIS_MODULE,
	.pf = PF_INET,
	.hooknum = NF_INET_PRE_ROUTING,
	.priority = NF_IP_PRI_FIRST
};   // NF_INET_PRE_ROUTING - for incoming packets
struct nf_hook_ops input_nat_filter = {
	.hook = (nf_hookfn *)hook_func_nat_in,
	.owner = THIS_MODULE,
	.pf = PF_INET,
	.hooknum = NF_INET_PRE_ROUTING,
	.priority = NF_IP_PRI_NAT_DST
};
struct nf_hook_ops output_nat_filter = {
	.hook = (nf_hookfn *)hook_func_nat_out,
	.owner = THIS_MODULE,
	.pf = PF_INET,
	.hooknum = NF_INET_POST_ROUTING,
	.priority = NF_IP_PRI_NAT_SRC
};

/*-----------------------------------tools begin------------------------------------------*/
bool IsMatch(unsigned ip, const char *ip_range){
    char tmp_ip[20];
    int p = -1, count = 0;
    unsigned len = 0, tmp = 0, mask = 0, r_ip = 0,i;
    strcpy(tmp_ip, ip_range);
    for(i = 0; i < strlen(tmp_ip); i++){
        if(p != -1){
            len *= 10;
            len += tmp_ip[i] - '0';
        }
        else if(tmp_ip[i] == '/')
            p = i;
    }
    if(p != -1){
        tmp_ip[p] = '\0';
        if(len)
            mask = 0xFFFFFFFF << (32 - len);
    }
    else mask = 0xFFFFFFFF;
    for(i = 0; i < strlen(tmp_ip); i++){
        if(tmp_ip[i] == '.'){
            r_ip = r_ip | (tmp << (8 * (3 - count)));
            tmp = 0;
            count++;
            continue;
        }
        tmp *= 10;
        tmp += tmp_ip[i] - '0';
    }
    r_ip = r_ip | tmp;
    return (r_ip & mask) == (ip & mask);
}

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
        (__u32)p[0], (__u32)p[1], (__u32)p[2], (__u32)p[3]);
    return buff;
}
void print_ip(unsigned long ip) {
    printk("%ld.%ld.%ld.%ld\n", (ip>>24)&0xff, (ip>>16)&0xff, (ip>>8)&0xff, (ip>>0)&0xff);
}

/*-----------------------------------hash begin---------------------------------------------*/
//初始化指针数组和所有链表的头结点
void InitHashList(void){
	int i = 0;
	for(;i < MAX_STATU_NUM; i++){
		cons[i] = (Connection*)kmalloc(sizeof(Connection), GFP_ATOMIC);
		cons[i]->next = NULL;
	}
}

//回收全部链表的内存空间
void DelHashList(void){
	Connection *tmp, *tmp1;
	int i = 0;
	for(;i < MAX_STATU_NUM; i++){
		tmp = cons[i]->next;
		cons[i]->next = NULL;
		while(tmp){
			tmp1 = tmp->next;
			kfree(tmp);
			tmp = tmp1;
		}		
	}
}

//在指针p指向的结点后面插入一个新结点
void InsertNode(Connection *p, unsigned src_ip, unsigned dst_ip, unsigned char protocol,
					unsigned short src_port, unsigned short dst_port){
	Connection *tmpNode;
	tmpNode = (Connection*)kmalloc(sizeof(Connection),GFP_ATOMIC);
	tmpNode->src_ip = src_ip;
	tmpNode->dst_ip = dst_ip;
	tmpNode->src_port = src_port;
	tmpNode->dst_port = dst_port;
	tmpNode->protocol = protocol;
	tmpNode->t = jiffies + 10 * HZ;
	tmpNode->next = p->next;
	p->next = tmpNode;
}

//检查是否已建立相同的连接。若不存在，则返回指针指向对应位置的链表的尾节点；若存在，则返回空指针
Connection* HashCheck(unsigned src_ip, unsigned dst_ip, unsigned char protocol,
					unsigned short src_port, unsigned short dst_port){
	char buff[20];
	unsigned p = (src_ip ^ dst_ip ^ protocol ^ src_port ^ src_port) % 101;
	Connection *cur_p = cons[p], *tmp_p;
	printk("hash place:%u\n", p);
	printk("src_ip:%s	", addr_from_net(buff,src_ip));
	printk("dst_ip:%s	", addr_from_net(buff,dst_ip));
	printk("src_port:%hu	", src_port);
	printk("dst_port:%hu	", dst_port);
	printk("protocol:%hhu\n", protocol);
	while(cur_p->next){
		//删除超时结点
		if(time_after(jiffies, cur_p->next->t)){   //time_after(a,b) returns true if the time a is after time b.
			tmp_p = cur_p->next;
			cur_p->next = cur_p->next->next;
			kfree(tmp_p);
			continue;
		}
		//如果与状态链接表中的结点匹配上了
		if((protocol == cur_p->next->protocol && src_ip == cur_p->next->src_ip && dst_ip == cur_p->next->dst_ip
			&& src_port == cur_p->next->src_port && dst_port == cur_p->next->dst_port) ||
			(protocol == cur_p->next->protocol && dst_ip == cur_p->next->src_ip && src_ip == cur_p->next->dst_ip
			&& dst_port == cur_p->next->src_port && src_port == cur_p->next->dst_port)){
				//刷新生存时间
			cur_p->next->t = jiffies + 10 * HZ;
			printk("hash check exist\n\n");
			return NULL;
		}
		cur_p = cur_p->next;
	}
	return cur_p;
}

//将当前有效的状态连接拷贝至数组con2中，便于打包发给用户态
void UpdateHashList(void){
	Connection *p, *tmp_p;
	int i;
	cnum = 0;
	for(i = 0; i < MAX_STATU_NUM; i++){
		p = cons[i];
		while(p->next){
			//添加到cons2中
			if(time_before(jiffies,p->next->t)){ //time_before(a,b) returns true if the time b is after time a.
				cons2[cnum].src_ip = ntohl(p->next->src_ip);
				cons2[cnum].dst_ip = ntohl(p->next->dst_ip);
				cons2[cnum].src_port = p->next->src_port;
				cons2[cnum].dst_port = p->next->dst_port;
				cons2[cnum].protocol = p->next->protocol;
				cons2[cnum].t = p->next->t;
				cons2[cnum].next = NULL;
				cnum++;
			}
			//删除节点
			else{
				tmp_p = p->next;
				p->next = p->next->next;
				kfree(tmp_p);
			}
			if(p->next)
				p = p->next;
		}
	}			
}


/*------------------------------------netlink begin--------------------------------------------------*/
void netlink_cleanup(void){
	netlink_kernel_release(nl_sk);
	device_destroy(cls, devId);
	class_destroy(cls);
	unregister_chrdev_region(devId, 1);
}

void netlink_init(void){
	if((alloc_chrdev_region(&devId, 0, 1, "stone-alloc-dev") ) != 0) {
		printk(KERN_WARNING "register dev id error\n");
		netlink_cleanup();
		return;
	}
	//动态创建设备节点
	cls = class_create(THIS_MODULE, "stone-class");
	if(IS_ERR(cls)) {
		printk(KERN_WARNING "create class error!\n");
		netlink_cleanup();
		return;
	}
	if(device_create(cls, NULL, devId, "", "hello%d", 0) == NULL) {
		printk(KERN_WARNING "create device error!\n");
		netlink_cleanup();
		return;
	}
	
	nl_sk = netlink_kernel_create(&init_net, NETLINK_TEST, &nkc);
	if(!nl_sk ) {
		printk(KERN_ERR "[netlink] create netlink socket error!\n");
		netlink_cleanup();
		return;
	}
	return;
}

//向进程pid发送长度为len的报文message
void netlink_send(int pid, uint8_t *message, int len){
	struct sk_buff *skb_1;
	struct nlmsghdr *nlh;
	if(!message || !nl_sk) {
		return;
	}
	skb_1 = alloc_skb(NLMSG_SPACE(len), GFP_ATOMIC);
	if( !skb_1 ) {
		printk(KERN_ERR "alloc_skb error!\n");
	}
	nlh = nlmsg_put(skb_1, 0, 0, 0, len, 0);
	NETLINK_CB(skb_1).portid = 0;
	NETLINK_CB(skb_1).dst_group = 0;
	memcpy(NLMSG_DATA(nlh), message, len);
	netlink_unicast(nl_sk, skb_1, pid, MSG_DONTWAIT);
}

//处理来自用户程序的报文
void netlink_input(struct sk_buff *__skb){
	int i;
	struct sk_buff *skb;
	char str[1000], buff[20], buff2[20];
	struct nlmsghdr *nlh;
	if( !__skb ) {
		return;
	}
	skb = skb_get(__skb);
	if( skb->len < NLMSG_SPACE(0)) {
		return;
	}
	nlh = nlmsg_hdr(skb);
	memset(str, 0, sizeof(str));
	memcpy(str, NLMSG_DATA(nlh), 1000);
	switch (str[0])   //根据发来的报文的第一个字符进行判断
	{
	case 0:
		//flush rules
		rnum = str[1];
		memcpy(rules, str + 2, rnum * sizeof(Rule));
		for(i = 0; i < rnum; i++){
			printk("\n\n\n\n\nrnum:%d\n", i);
			printk("src_ip:%s\n", rules[i].src_ip);
			printk("dst_ip:%s\n", rules[i].dst_ip);
			printk("src_port:%d\n", rules[i].src_port);
			printk("dst_port:%d\n", rules[i].dst_port);
			printk("protocol:%d\n", rules[i].protocol);
			printk("log:%d\n", rules[i].log);
			printk("action:%d\n", rules[i].action);
		}
		break;
	case 1:
		//flush nat rules
		nnum = str[1];
		memcpy(&net_ip, str + 2, sizeof(unsigned));
		memcpy(&net_mask, str + 6, sizeof(unsigned));
		memcpy(&firewall_ip, str + 10, sizeof(unsigned));
		memcpy(&natTable[1], str + 14, nnum * sizeof(NatEntry));
		natTable[0].firewall_port = 30001;
		natTable[0].nat_port = 30001;
		natTable[0].nat_ip = ipstr_to_num("192.168.142.129");
		nnum++;
		printk("\n\n\n\n\nglobal_fireip:%s\nnet_ip:%s\nnet_mask:%x\n", addr_from_net(buff,ntohl(firewall_ip)), addr_from_net(buff2,ntohl(net_ip)), net_mask);
		for(i = 0; i < nnum; i++){
			printk("nnum:%d\n", i);
			printk("nat_ip:%s\nfirewall_port:%u\nnat_port:%u\n", addr_from_net(buff2, natTable[i].nat_ip), natTable[i].firewall_port, natTable[i].nat_port);
		}
		break;
	case 2:
		//get logs
		for(i = 0; i < lnum; i++){
			printk("\n\n\n\n\nlnum:%d\n", i+1);
			printk("src_ip:%s\n", addr_from_net(buff,ntohl(logs[i].src_ip)));
			printk("dst_ip:%s\n", addr_from_net(buff,ntohl(logs[i].dst_ip)));
			printk("src_port:%hu\n", logs[i].src_port);
			printk("dst_port:%hu\n", logs[i].dst_port);
			printk("protocol:%hhu\n", logs[i].protocol);
			printk("action:%hhu\n", logs[i].action);
		}
		printk("msgLen:%d\n",lnum * sizeof(Log));
		netlink_send(nlh->nlmsg_pid, (uint8_t *)logs, lnum * sizeof(Log));
		break;
	case 3:
		//get connections
		UpdateHashList();
		for(i = 0; i < cnum; i++){
			printk("\n\n\n\n\ncnum:%d\n", i+1);
			printk("src_ip:%s\n", addr_from_net(buff,ntohl(cons2[i].src_ip)));
			printk("dst_ip:%s\n", addr_from_net(buff,ntohl(cons2[i].dst_ip)));
			printk("src_port:%hu\n", cons2[i].src_port);
			printk("dst_port:%hu\n", cons2[i].dst_port);
			printk("protocol:%hhu\n", cons2[i].protocol);
		}
		netlink_send(nlh->nlmsg_pid, (uint8_t *)cons2, cnum * sizeof(Connection));
	default:
		break;
	}
	return;
}


/*------------------------------------hook function--------------------------------------------------*/
void GetPort(struct sk_buff *skb, struct iphdr *hdr, unsigned short *src_port, unsigned short *dst_port){
	struct tcphdr *mytcphdr;
	struct udphdr *myudphdr;
	switch(hdr->protocol){
		case TCP:
			mytcphdr = (struct tcphdr *)(skb->data + (hdr->ihl * 4));
			*src_port = ntohs(mytcphdr->source);
			*dst_port = ntohs(mytcphdr->dest);
			break;
		case UDP:
			myudphdr = (struct udphdr *)(skb->data + (hdr->ihl * 4));
			*src_port = ntohs(myudphdr->source);
			*dst_port = ntohs(myudphdr->dest);
			break;
		case ICMP:
			*src_port = 30001;
			*dst_port = 30001;
			break;
		default:
			printk("WARNING:UNKNOW PROTOCOL\n");
			*src_port = 0;
			*dst_port = 0;
			break;
	}
}

//check the connect list
unsigned int hook_func(unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int(*okfn)(struct sk_buff*))
{
	int i;
	Connection *p;
	short src_port, dst_port;
	struct iphdr *hdr;
	hdr = ip_hdr(skb);
	
	//get port information
	GetPort(skb, hdr, &src_port, &dst_port);
	//connect list
	//HashCheck检查是否已建立相同的连接。若不存在，则返回指针指向对应位置的链表的尾节点；若存在，则返回空指针
	p = HashCheck(hdr->saddr, hdr->daddr, hdr->protocol, src_port, dst_port);
	if(!p) return NF_ACCEPT;

	//rules matching
	//规则匹配了 同时有空插入connection哈希表
	for(i = 0; i < rnum;i ++){
		printk("matching the %dth rules......\n", i);
		if(strcmp(rules[i].src_ip, "any") && !IsMatch(ntohl(hdr->saddr), rules[i].src_ip)) continue;
		if(strcmp(rules[i].dst_ip, "any") && !IsMatch(ntohl(hdr->daddr), rules[i].dst_ip)) continue;
		if(rules[i].protocol != ANY && rules[i].protocol != hdr->protocol) continue;
		if(rules[i].src_port != ANY && src_port != rules[i].src_port) continue;
		if(rules[i].dst_port != ANY && dst_port != rules[i].dst_port) continue;
		if(rules[i].log ){
			if(lnum >= 60){
				for(lnum = 0; lnum < 30; lnum++)
					logs[lnum] = logs[lnum+30];
			}
			logs[lnum].dst_ip = ntohl(hdr->daddr);
			logs[lnum].src_ip = ntohl(hdr->saddr);
			logs[lnum].dst_port = dst_port;
			logs[lnum].src_port = src_port;
			logs[lnum].protocol = hdr->protocol;
			logs[lnum].action = rules[i].action;
			lnum++;
		}
		if(rules[i].action){  //action = 1 表示允许
			InsertNode(p, hdr->saddr, hdr->daddr, hdr->protocol, src_port, dst_port);
			printk("Insert a hash Node!\n\n");
			return NF_ACCEPT;
		}
		else return NF_DROP;
	}
	
	//默认放行
	InsertNode(p, hdr->saddr, hdr->daddr, hdr->protocol, src_port, dst_port);
	printk("Insert a hash Node!\n\n");
	
	return NF_ACCEPT;
}

//进入防火墙时 进行的nat转化hook
unsigned int hook_func_nat_in(unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int(*okfn)(struct sk_buff*))
{
	int i, tot_len, hdr_len;
	unsigned short src_port, dst_port;
	struct iphdr *hdr;
	struct tcphdr *tcph;
	struct udphdr *udph;
	hdr = ip_hdr(skb);
	printk("this pkt src ip is ");
	print_ip(ntohl(hdr->saddr));
	printk("this pkt dst ip is ");
	print_ip(ntohl(hdr->daddr));
	GetPort(skb, hdr, &src_port, &dst_port);
	printk("src_port:%hu dst_port:%hu\n", src_port, dst_port);
	for(i = 0; i < nnum; i++){
		if(ntohl(hdr->daddr) == firewall_ip && dst_port == natTable[i].firewall_port){
			printk("match dnat rules!\n");
			hdr->daddr = ntohl(natTable[i].nat_ip);
			hdr_len = ip_hdrlen(skb);
			tot_len = ntohs(hdr->tot_len);
			hdr->check = 0;
			hdr->check = ip_fast_csum(hdr,hdr->ihl);

			switch(hdr->protocol) {
				case TCP:
					tcph = (struct tcphdr *)(skb->data + (hdr->ihl * 4));
					tcph->dest = htons(natTable[i].nat_port);
					tcph->check = 0;
					skb->csum = csum_partial((unsigned char *)tcph, tot_len - hdr_len,0);
					tcph->check = csum_tcpudp_magic(hdr->saddr, hdr->daddr,
					ntohs(hdr->tot_len) - hdr_len,hdr->protocol,skb->csum);
					break;
				case UDP:
					udph = (struct udphdr *)(skb->data + (hdr->ihl * 4));
					udph->dest = htons(natTable[i].nat_port);
					udph->check = 0;
					skb->csum = csum_partial((unsigned char *)udph, tot_len - hdr_len,0);
					udph->check = csum_tcpudp_magic(hdr->saddr, hdr->daddr,
					ntohs(hdr->tot_len) - hdr_len, hdr->protocol, skb->csum);
					break;
				case ICMP:
					break;
			}

			printk("this pkt src ip is ");
			print_ip(ntohl(hdr->saddr));
			printk("this pkt dst ip is ");
			print_ip(ntohl(hdr->daddr));
			printk("\n");
			return NF_ACCEPT;
		}
	}
	
	printk("this pkt src ip is ");
	print_ip(ntohl(hdr->saddr));
	printk("this pkt dst ip is ");
	print_ip(ntohl(hdr->daddr));
	printk("\n");
	return NF_ACCEPT;
}

//进行源地址nat转换，如果nat列表中不存在，则添加一条
unsigned int hook_func_nat_out(unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int(*okfn)(struct sk_buff*))
{
	int i, tot_len, hdr_len;
	unsigned short src_port, dst_port;
	struct iphdr *hdr;    
	struct tcphdr *tcph;
	struct udphdr *udph;
	hdr = ip_hdr(skb);
	printk("nat out:%s->%s\n", in->name, out->name);
	printk("this pkt src ip is ");
	print_ip(ntohl(hdr->saddr));
	printk("this pkt dst ip is ");
	print_ip(ntohl(hdr->daddr));
	GetPort(skb, hdr, &src_port, &dst_port);
	printk("src_port:%u dst_port:%u\n", src_port, dst_port);
	for(i = 0; i < nnum; i++){
		if(ntohl(hdr->saddr) == natTable[i].nat_ip && src_port == natTable[i].nat_port){
			printk("match snat rules!\n");	
			hdr->saddr = ntohl(firewall_ip);
			hdr_len = ip_hdrlen(skb);
			tot_len = ntohs(hdr->tot_len);
			hdr->check = 0;
			hdr->check = ip_fast_csum(hdr,hdr->ihl);

			switch(hdr->protocol) {
				case TCP:
					tcph = (struct tcphdr *)(skb->data + (hdr->ihl * 4));
					tcph->source = htons(natTable[i].firewall_port);
					tcph->check = 0;
					skb->csum = csum_partial((unsigned char *)tcph, tot_len - hdr_len,0);
					tcph->check = csum_tcpudp_magic(hdr->saddr,hdr->daddr,
						ntohs(hdr->tot_len) - hdr_len,hdr->protocol,skb->csum);
					break;
				case UDP:
					udph = (struct udphdr *)(skb->data + (hdr->ihl * 4));
					udph->source = htons(natTable[i].firewall_port);
					udph->check = 0;
					skb->csum = csum_partial((unsigned char *)udph, tot_len - hdr_len,0);
					udph->check = csum_tcpudp_magic(hdr->saddr, hdr->daddr,
						ntohs(hdr->tot_len) - hdr_len,hdr->protocol, skb->csum);
					break;
				case ICMP:
					break;
			}

			printk("this pkt src ip is ");
			print_ip(ntohl(hdr->saddr));
			printk("this pkt dst ip is ");
			print_ip(ntohl(hdr->daddr));
			printk("\n");
			return NF_ACCEPT;
		}
	}

	if((ntohl(hdr->saddr) & net_mask) == (net_ip & net_mask)){
		printk("add a nat rule!\n");
		if(hdr->protocol == ICMP){
			natTable[0].nat_ip = ntohl(hdr->saddr);
			natTable[0].nat_port = 30001;
			natTable[0].firewall_port = 30001;
			return NF_REPEAT;  //创建成功 要保留该报文包
		}
		natTable[nnum].nat_ip = ntohl(hdr->saddr);
		natTable[nnum].nat_port = src_port;
		natTable[nnum].firewall_port = firewall_port;
		firewall_port++;
		nnum++;
		return NF_REPEAT;  //创建成功 要保留该报文包
	}

	printk("this pkt src ip is ");
	print_ip(ntohl(hdr->saddr));
	printk("this pkt dst ip is ");
	print_ip(ntohl(hdr->daddr));
	printk("\n");
	return NF_ACCEPT;
}

int myfw_init(void)
{
	nf_register_hook(&input_filter);
	nf_register_hook(&input_nat_filter);
	nf_register_hook(&output_nat_filter);
	InitHashList();
	netlink_init();
	return 0;
}

void myfw_exit(void)
{
	printk("kexec test exit...\n");
	nf_unregister_hook(&input_filter);
	nf_unregister_hook(&input_nat_filter);
	nf_unregister_hook(&output_nat_filter);
	DelHashList();
	netlink_cleanup();
}

module_init(myfw_init);
module_exit(myfw_exit);
