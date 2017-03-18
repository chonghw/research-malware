#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <gtk/gtk.h>
#include "interface.h"
#include "support.h"
#include "callbacks.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>

int
main (int argc, char *argv[])
{
  int i;
  char *tmp;
  int sock = -1;
  GtkWidget *window1;
  int addrlen;
  int inlen = 2048;
  char *in;
  struct sockaddr_in caddr, saddr;
  struct timeval tv;
  fd_set fds;

  in = (char *) malloc(inlen);
  srand((unsigned int) time(NULL));

#ifdef ENABLE_NLS
	bindtextdomain (PACKAGE, PACKAGE_LOCALE_DIR);
	textdomain (PACKAGE);
#endif

  gtk_set_locale ();
  gtk_init (&argc, &argv);

  add_pixmap_directory (PACKAGE_DATA_DIR "/pixmaps");
  add_pixmap_directory (PACKAGE_SOURCE_DIR "/pixmaps");

  window1 = create_window ();
  gtk_widget_show (window1);
  
	for(i=1;i<argc;i++)
	{
		if(strcmp("-c", argv[i]) == 0)
			load_client(argv[i+1]);
		if(strcmp("-s", argv[i]) == 0)
			load_server(argv[i+1]);
	}
	
	while(quit)
	{
		gtk_main_iteration();
		if(results)
		{

		if(port != resultsport)
		{
			port = resultsport;
			if(sock != -1)
			{
				shutdown(sock, 2);
				close(sock);
			}
			saddr.sin_addr.s_addr = resultshost;
			saddr.sin_port = port;
			saddr.sin_family = AF_INET;
			sock = socket(AF_INET, SOCK_DGRAM, 0);
			if(sock == -1)
				write_text("client error: error creating listening socket\r\n");
			else
			{
				if(bind(sock, (struct sockaddr *) &saddr, sizeof(saddr)) < 0)
				{
					shutdown(sock, 2);
					close(sock);
					sock = -1;
					write_text("client error: error binding listening socket\r\n");	
				}
				else
					write_text("bound\r\n");
			}
			
		}
		
		if(sock != -1)
		{
			FD_ZERO(&fds);
			FD_SET(sock, &fds);
			tv.tv_sec = 0;
			tv.tv_usec = 0;
			if(select(sock + 1, &fds, NULL, NULL, &tv) > 0)
			{
				addrlen = sizeof(caddr);
				memset(in, 0, inlen);
				i = recvfrom(sock, in, inlen, 0, (struct sockaddr *) &caddr, &addrlen);
				switch(*in)
				{
					case '0':
						write_text(in+1);
						break;
					case '1':
						tmp = strstr(in, ":");
						if(tmp == NULL)
							break;
						*tmp = 0;
						tmp++;
						tmp = strstr(tmp, "\r");
						if(tmp == NULL)
							break;
						*tmp = 0;
						tmp = in + 1;
						if(ctree_node == NULL)
						{
							write_text("add of function failed\r\n");
							break;
						}
						if(strcmp(menuname, tmp) != 0)
							ctree_node = add_ctree_node(tmp, "", NULL);
						add_ctree_node(tmp+strlen(tmp) + 1, "", ctree_node);
						break;
					case '2':
						build_ctree();
						break;
					default:
						write_text("unknown packet recieved\r\n");
						break;
				}
			}
		}
		}
	} 

	if(sock != -1)
	{
		shutdown(sock, 2);
		close(sock);
	}
	free(in);

  return 0;
}

