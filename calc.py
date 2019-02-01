#start = 0x00004970
#end = 0x000073b0
#print(hex(start - 0x00003fc6))


HDR_MAGIC	= 0x00008000

def compute_magic(f, b):
	# _MAGIC(f, b)           ((f)|((((4*(b))+0)*(b))+7))
	return '{0:08x}'.format((f)|((((4*(b))+0)*(b))+7))

print(compute_magic(0, 25))