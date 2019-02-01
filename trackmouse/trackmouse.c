#include <u.h>
#include <libc.h>

#define width 49
#define b1 1
#define b2 2
#define b3 4

/* Tracks which mouse buttons are pressed at a given time */
void
main()
{
	int fd = open("/dev/mouse", OREAD);
	char last = 'x';
	for(;;){
		// see: mouse(3)
		char buf[width];
		read(fd, buf, width);
		char button = buf[35];
		if(button != last){
			switch(button){
			case '0'+b1:
				print("\Left button pressed.\n");
				break;
			case '0'+b2:
				print("Middle button pressed.\n");
				break;
			case '0'+b3:
				print("Right button pressed.\n");
				break;
			case '0'+(b1|b2):
				print("Left and Middle buttons pressed.\n");
				break;
			case '0'+(b1|b3):
				print("Left and Right buttons pressed.\n");
				break;
			case '0'+(b2|b3):
				print("Middle and Right buttons pressed.\n");
				break;
			case '0'+(b1|b2|b3):
				print("All buttons pressed.\n");
				break;
			case '0':
				print("No buttons pressed.\n");
				break;
			}
			last = button;
		}
	}
}
