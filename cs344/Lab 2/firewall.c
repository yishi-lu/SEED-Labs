#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>


static struct nf_hook_ops filterHook;

unsigned int myFilter(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
  struct iphdr *iph;
  struct tcphdr *tcph;
  char ip_src[16],ip_dst[16];

  iph = ip_hdr(skb);
  tcph = (void *)iph+iph->ihl*4;

  //get source IP address in char array
  sprintf(ip_dst, "%d.%d.%d.%d", ((unsigned char *)&iph->daddr)[0], ((unsigned char *)&iph->daddr)[1], 
		((unsigned char *)&iph->daddr)[2], ((unsigned char *)&iph->daddr)[3]);
  //get destination IP address in char array
  sprintf(ip_src, "%d.%d.%d.%d", ((unsigned char *)&iph->saddr)[0], ((unsigned char *)&iph->saddr)[1], 
		((unsigned char *)&iph->saddr)[2], ((unsigned char *)&iph->saddr)[3]);
	
  //prevent VM A telnet VM B
  if (iph->protocol == IPPROTO_TCP && (tcph->dest == htons(23) || tcph->source == htons(23)) && strcmp(ip_dst, "10.0.2.5") == 0) {
    printk(KERN_INFO "Dropping telnet packet to %s\n", ip_dst);
    return NF_DROP;
  } 

  //prevent VM B telnet VM A
  if (iph->protocol == IPPROTO_TCP && (tcph->dest == htons(23) || tcph->source == htons(23)) && strcmp(ip_src, "10.0.2.5") == 0) {
    printk(KERN_INFO "Dropping telnet packet from %s\n",ip_src);
    return NF_DROP;
  } 

  //prevent host machine to visit www.syracuse.edu
  if (strcmp(ip_dst, "128.230.18.198") == 0){
	 printk(KERN_INFO "Dropping packet to %s\n", ip_dst);
    return NF_DROP;
  }

  //prevent ICMP request/reply from VM B (10.0.2.5)
  if (iph->protocol == IPPROTO_ICMP && strcmp(ip_src, "10.0.2.5") == 0){
	 printk(KERN_INFO "Dropping ICMP packet from VM B %s", ip_src);
    return NF_DROP;
  }

  //prevent host machine to visit www2.cuny.edu
  if(strcmp(ip_dst, "128.228.0.52") == 0){
  	printk(KERN_INFO "Dropping packet to %s\n", ip_dst);
    return NF_DROP;
  }


  return NF_ACCEPT;
}

/* The implementation of the telnetFilter function is omitted here; 
   it was shown earlier in (*@Listing~\ref{firewall:code:telnetFilter}@*). */

int setUpFilter(void) {
	printk(KERN_INFO "Registering a filter.\n");
	filterHook.hook = myFilter; //(*@\label{firewall:line:telnetHookfn}@*)
	filterHook.hooknum = NF_INET_PRE_ROUTING; 
	filterHook.pf = PF_INET;
	filterHook.priority = NF_IP_PRI_FIRST;

	// Register the hook.
	nf_register_net_hook(&init_net,&filterHook);
	return 0;
}

void removeFilter(void) {
	printk(KERN_INFO "The filter is being removed.\n");
	nf_unregister_net_hook(&init_net,&filterHook);
}

module_init(setUpFilter);
module_exit(removeFilter);

MODULE_LICENSE("GPL");