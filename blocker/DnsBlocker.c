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

#define DNS_PORT 53
#define MAX_DNS_NAME_LEN 256
#define MAX_BLACKLIST_ENTRIES 100

static struct nf_hook_ops *nfho = NULL;
static char *blacklist[MAX_BLACKLIST_ENTRIES];
static int blacklist_size = 0;

#include <linux/string.h> // For strim()

static int load_blacklist(const char *filename)
{
    struct file *file;
    char *buf;
    ssize_t bytes_read;
    loff_t pos = 0;
    int i = 0;

    file = filp_open(filename, O_RDONLY, 0);
    if (IS_ERR(file))
    {
        pr_err("Cannot open blacklist file: %s\n", filename);
        return -1;
    }

    buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!buf)
    {
        filp_close(file, NULL);
        return -1;
    }

    while ((bytes_read = kernel_read(file, buf, PAGE_SIZE, &pos)) > 0 && i < MAX_BLACKLIST_ENTRIES)
    {
        char *line = buf;
        char *end;

        // Null-terminate the buffer
        buf[bytes_read] = '\0';

        // Process each line
        while ((end = strsep(&line, "\n")) != NULL)
        {
            char *comment_pos;

            // Remove comments after '#'
            comment_pos = strchr(end, '#');
            if (comment_pos)
            {
                *comment_pos = '\0'; // Truncate line at '#'
            }

            // Trim leading/trailing spaces
            strim(end);

            // Skip empty lines or fully commented lines
            if (strlen(end) == 0)
            {
                continue;
            }

            // Store the valid DNS entry in the blacklist array
            blacklist[i] = kstrdup(end, GFP_KERNEL);
            if (!blacklist[i])
            {
                pr_err("Memory allocation failed for blacklist entry %d\n", i);
                break;
            }

            pr_info("Loaded blacklist domain: %s\n", blacklist[i]);
            i++;

            if (i >= MAX_BLACKLIST_ENTRIES)
            {
                pr_err("Reached maximum port capacity of %d entries\n", MAX_BLACKLIST_ENTRIES);
                break;
            }
        }
    }

    filp_close(file, NULL);
    kfree(buf);

    blacklist_size = i;
    return 0;
}
static bool is_blacklisted(const char *domain)
{
    int i;
    for (i = 0; i < blacklist_size; i++)
    {
        if (strncasecmp(domain, blacklist[i], MAX_DNS_NAME_LEN) == 0)
        {
            return true;
        }
    }
    return false;
}

// Improved DNS name extraction function
static void extract_dns_query_name(char *dns_payload, char *dns_name, int max_len)
{
    int i = 0, j = 0, len;

    while (i < max_len && (len = dns_payload[i++]))
    {
        if (len + i >= max_len)
            break; // Avoid going out of bounds

        if (j > 0)
        {
            dns_name[j++] = '.'; // Add dots between labels
        }

        while (len-- && j < max_len - 1)
        {
            dns_name[j++] = dns_payload[i++];
        }
    }
    dns_name[j] = '\0'; // Null-terminate the name
}

static unsigned int dns_filter(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    static unsigned short sniff_ports_list[] = {53, 80, 443}; // DNS, HTTP, HTTPS
#define NUM_SNIFF_PORTS (sizeof(sniff_ports_list) / sizeof(sniff_ports_list[0]))

    struct iphdr *iph;
    struct udphdr *udph;
    char *dns_payload;
    char dns_name[MAX_DNS_NAME_LEN];

    iph = ip_hdr(skb);
    if (iph->protocol != IPPROTO_UDP)
        return NF_ACCEPT;

    udph = udp_hdr(skb);
    if (ntohs(udph->dest) != DNS_PORT)
        return NF_ACCEPT;

    dns_payload = (char *)((unsigned char *)udph + sizeof(struct udphdr));

    // Extract domain name from DNS payload using improved function
    extract_dns_query_name(dns_payload + 12, dns_name, MAX_DNS_NAME_LEN);

    // Check if the domain is blacklisted
    if (is_blacklisted(dns_name))
    {
        pr_info("Blocked DNS request to %s\n", dns_name);
        return NF_DROP;
    }
    return NF_ACCEPT;
}

static int __init dns_filter_init(void)
{
    nfho = (struct nf_hook_ops *)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    if (!nfho)
    {
        return -ENOMEM;
    }

    nfho->hook = dns_filter;
    nfho->hooknum = NF_INET_PRE_ROUTING;
    nfho->pf = PF_INET;
    nfho->priority = NF_IP_PRI_FIRST;

    if (nf_register_net_hook(&init_net, nfho))
    {
        kfree(nfho);
        pr_err("Failed to register netfilter hook\n");
        return -1;
    }

    pr_info("DNS Filter Module Loaded\n");

    load_blacklist("/etc/blacklist.txt");

    return 0;
}

static void __exit dns_filter_exit(void)
{
    nf_unregister_net_hook(&init_net, nfho);
    kfree(nfho);
    pr_info("DNS Filter Module Unloaded\n");
}

module_init(dns_filter_init);
module_exit(dns_filter_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Maximoniy");
MODULE_DESCRIPTION("Module to filter dns addresess of forbiden sites 18+ from dataset loaded from interenet");
