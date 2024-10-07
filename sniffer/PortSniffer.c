#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/string.h>

#define MAX_PORTS 1000        // Max number of ports to read
#define MAX_PORT_STRING_LEN 6 // Max length of a port number in string form

static unsigned short *sniff_ports_list = NULL; // Dynamically allocated port list
static int sniff_ports_count = 0;               // Number of ports in the list
static struct nf_hook_ops *nfho = NULL;

// Function to read ports from "/etc/portlist.txt" and populate sniff_ports_list
static int load_sniff_ports(const char *filename)
{
    struct file *file;
    char *buf;
    ssize_t bytes_read;
    loff_t pos = 0;
    int i = 0;

    // Open the file
    file = filp_open(filename, O_RDONLY, 0);
    if (IS_ERR(file))
    {
        pr_err("Cannot open port list file: %s\n", filename);
        return -1;
    }

    // Allocate memory for port list
    sniff_ports_list = kmalloc_array(MAX_PORTS, sizeof(unsigned short), GFP_KERNEL);
    if (!sniff_ports_list)
    {
        filp_close(file, NULL);
        return -ENOMEM;
    }

    // Allocate buffer to read file content
    buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!buf)
    {
        kfree(sniff_ports_list);
        filp_close(file, NULL);
        return -ENOMEM;
    }

    // Read file content line by line
    while ((bytes_read = kernel_read(file, buf, PAGE_SIZE, &pos)) > 0 && i < MAX_PORTS)
    {
        char *line = buf;
        char *end;

        // Null-terminate the buffer
        buf[bytes_read] = '\0';

        // Process each line
        while ((end = strsep(&line, "\n")) != NULL)
        {
            unsigned long port;
            int ret = kstrtoul(end, 10, &port); // Convert string to unsigned long
            if (ret == 0 && port <= 65535)
            {
                sniff_ports_list[i++] = (unsigned short)port; // Store the port number
                pr_info("Loaded port: %lu\n", port);
            }
        }
    }

    sniff_ports_count = i; // Store the number of ports loaded
    pr_info("Total loaded ports: %d\n", sniff_ports_count);

    // Cleanup
    kfree(buf);
    filp_close(file, NULL);

    return 0;
}

// Filtering function (similar to what you had)
static unsigned int dns_filter(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct udphdr *udph;
    struct tcphdr *tcph;

    iph = ip_hdr(skb);

    // Check if the packet is either UDP or TCP
    if (iph->protocol == IPPROTO_UDP)
    {
        udph = udp_hdr(skb);

        // Check if the destination port is in the sniff_ports_list
        for (int i = 0; i < sniff_ports_count; i++)
        {
            if (ntohs(udph->dest) == sniff_ports_list[i])
            {
                pr_info("sniffed UDP [%pI4, %u]\n", &iph->saddr, ntohs(udph->dest)); // Log UDP IP and port
                break;
            }
        }
    }
    else if (iph->protocol == IPPROTO_TCP)
    {
        tcph = tcp_hdr(skb);

        // Check if the destination port is in the sniff_ports_list
        for (int i = 0; i < sniff_ports_count; i++)
        {
            if (ntohs(tcph->dest) == sniff_ports_list[i])
            {
                pr_info("sniffed TCP [%pI4, %u]\n", &iph->saddr, ntohs(tcph->dest)); // Log TCP IP and port
                break;
            }
        }
    }

    return NF_ACCEPT;
}

static int __init dns_filter_init(void)
{
    int ret;

    // Load sniffed ports from file
    ret = load_sniff_ports("/etc/portlist.txt");
    if (ret < 0)
    {
        pr_err("Failed to load ports\n");
        return ret;
    }

    nfho = (struct nf_hook_ops *)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    if (!nfho)
    {
        return -ENOMEM;
    }

    nfho->hook = dns_filter;
    nfho->hooknum = NF_INET_POST_ROUTING; // Use POST_ROUTING for outgoing packets
    nfho->pf = PF_INET;
    nfho->priority = NF_IP_PRI_FIRST;

    if (nf_register_net_hook(&init_net, nfho))
    {
        kfree(nfho);
        pr_err("Failed to register netfilter hook\n");
        return -1;
    }

    pr_info("PortSniffer Module Loaded\n");
    return 0;
}

static void __exit dns_filter_exit(void)
{
    nf_unregister_net_hook(&init_net, nfho);
    kfree(nfho);
    kfree(sniff_ports_list); // Free the dynamically allocated port list
    pr_info("DNS Filter Module Unloaded\n");
}

module_init(dns_filter_init);
module_exit(dns_filter_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Maximoniy");
MODULE_DESCRIPTION("Module to filter DNS and HTTP/HTTPS ports using a dynamic port list");
