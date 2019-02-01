#!/usr/bin/env python
import struct, sys
from capstone import *
'''
NAME
        a.out - object file format

   SYNOPSIS
        #include <a.out.h>

   DESCRIPTION
        An executable Plan 9 binary file has up to six sections: a
        header, the program text, the data, a symbol table, a PC/SP
        offset table (MC68020 only), and finally a PC/line number
        table.  The header, given by a structure in <a.out.h>, con-
        tains 4-byte integers in big-endian order:

        typedef struct Exec {
                 long       magic;      /* magic number */
                 long       text;       /* size of text segment */
                 long       data;       /* size of initialized data */
                 long       bss;        /* size of uninitialized data */
                 long       syms;       /* size of symbol table */
                 long       entry;      /* entry point */
                 long       spsz;       /* size of pc/sp offset table */
                 long       pcsz;       /* size of pc/line number table */
        } Exec;

        #define HDR_MAGIC   0x00008000

        #define  _MAGIC(f, b)           ((f)|((((4*(b))+0)*(b))+7))
        #define  A_MAGIC    _MAGIC(0, 8)        /* 68020 */
        #define  I_MAGIC    _MAGIC(0, 11)       /* intel 386 */
        #define  J_MAGIC    _MAGIC(0, 12)       /* intel 960 (retired) */
        #define  K_MAGIC    _MAGIC(0, 13)       /* sparc */
        #define  V_MAGIC    _MAGIC(0, 16)       /* mips 3000 BE */
        #define  X_MAGIC    _MAGIC(0, 17)       /* att dsp 3210 (retired) */
        #define  M_MAGIC    _MAGIC(0, 18)       /* mips 4000 BE */
        #define  D_MAGIC    _MAGIC(0, 19)       /* amd 29000 (retired) */
        #define  E_MAGIC    _MAGIC(0, 20)       /* arm */
        #define  Q_MAGIC    _MAGIC(0, 21)       /* powerpc */
        #define  N_MAGIC    _MAGIC(0, 22)       /* mips 4000 LE */
        #define  L_MAGIC    _MAGIC(0, 23)       /* dec alpha (retired) */
        #define  P_MAGIC    _MAGIC(0, 24)       /* mips 3000 LE */
        #define  U_MAGIC    _MAGIC(0, 25)       /* sparc64 */
        #define  S_MAGIC    _MAGIC(HDR_MAGIC, 26)   /* amd64 */
        #define  T_MAGIC    _MAGIC(HDR_MAGIC, 27)   /* powerpc64 */
        #define  R_MAGIC    _MAGIC(HDR_MAGIC, 28)   /* arm64 */

        Sizes are expressed in bytes.  The size of the header is not
        included in any of the other sizes.
'''

'''
[blurbdust@X1C]: ~/Documents/parse.a.out>$ hexdump -C trackmouse/6.out | head
00000000  00 00 8a 97 00 00 3f 6f  00 00 0a c8 00 00 04 08  |......?o........|
00000010  00 00 28 6a 00 20 00 bd  00 00 00 00 00 00 0c 08  |..(j. ..........|
00000020  00 00 00 00 00 20 00 bd  48 83 ec 60 bd 88 09 40  |..... ..H..`...@|
00000030  00 c7 44 24 08 00 00 00  00 e8 1d 01 00 00 89 44  |..D$...........D|
00000040  24 5c c6 44 24 5b 78 8b  6c 24 5c 48 8d 7c 24 2a  |$\.D$[x.l$\H.|$*|
00000050  48 89 7c 24 08 bf 31 00  00 00 89 7c 24 10 e8 16  |H.|$..1....|$...|
00000060  01 00 00 0f be 7c 24 4d  40 88 7c 24 29 0f be 7c  |.....|$M@.|$)..||
00000070  24 29 40 3a 7c 24 5b 74  ce 0f be 7c 24 29 83 ff  |$)@:|$[t...|$)..|
00000080  31 74 2e 83 ff 32 74 1d  83 ff 34 74 0c 0f be 7c  |1t...2t...4t...||
00000090  24 29 40 88 7c 24 5b eb  ae bd c1 09 40 00 e8 8e  |$)@.|$[.....@...|
'''

'''
00000000  7f 45 4c 46 02 01 01 00  00 00 00 00 00 00 00 00  |.ELF............|
00000010  03 00 3e 00 01 00 00 00  e0 5a 00 00 00 00 00 00  |..>......Z......|
00000020  40 00 00 00 00 00 00 00  68 13 02 00 00 00 00 00  |@.......h.......|
00000030  00 00 00 00 40 00 38 00  0b 00 40 00 19 00 18 00  |....@.8...@.....|
00000040  06 00 00 00 04 00 00 00  40 00 00 00 00 00 00 00  |........@.......|
00000050  40 00 00 00 00 00 00 00  40 00 00 00 00 00 00 00  |@.......@.......|
00000060  68 02 00 00 00 00 00 00  68 02 00 00 00 00 00 00  |h.......h.......|
00000070  08 00 00 00 00 00 00 00  03 00 00 00 04 00 00 00  |................|
00000080  a8 02 00 00 00 00 00 00  a8 02 00 00 00 00 00 00  |................|
00000090  a8 02 00 00 00 00 00 00  1c 00 00 00 00 00 00 00  |................|

'''
sum_ = 0


HDR_MAGIC	= 0x00008000
def compute_magic(f, b):
	# _MAGIC(f, b)           ((f)|((((4*(b))+0)*(b))+7))
	return '{0:08x}'.format((f)|((((4*(b))+0)*(b))+7))
	
def check_magic(magic_bytes):
	magic_dict = {
		b'\x00\x00\x01\x07': "68020",
		b'\x00\x00\x01\xeb': "intel 386",
		b'\x00\x00\x02\x47': "intel 960",
		b'\x00\x00\x02\xab': "sparc",
		b'\x00\x00\x04\x07': "mips 3000 BE", #32
		b'\x00\x00\x04\x8b': "att dsp 3210",
		b'\x00\x00\x05\x17': "mips 4000 BE", #64
		b'\x00\x00\x05\xab': "amd 29000",
		b'\x00\x00\x06\x47': "arm",
		b'\x00\x00\x06\xeb': "powerpc",
		b'\x00\x00\x07\x97': "mips 4000 LE",
		b'\x00\x00\x08\x4b': "dec alpha",
		b'\x00\x00\x09\x07': "mips 3000 LE",
		b'\x00\x00\x09\xcb': "sparc64",
		b'\x00\x00\x8a\x97': "amd64",
		b'\x00\x00\x8b\x6b': "powerpc64",
		b'\x00\x00\x8c\x47': "arm64",
	}
	try:
		return magic_dict[magic_bytes]
	except:
		return "Not a valid a.out file"

def ret_int_hex_size(size):
	global sum_
	dec = int.from_bytes(size, byteorder='big')
	hex_ = '0x{0:08x}'.format(int.from_bytes(size, byteorder='big'))
	sum_ += int.from_bytes(size, byteorder='big') + 0x18 # padding
	sum_hex = '0x{0:08x}'.format(sum_)
	binja = '0x{0:08x}'.format(sum_ + 0x00200114)
	#print("SUM: {0:0d}".format(sum_))
	return f"{dec}\t{hex_}\t{sum_hex}\t{binja}"

def bytes_to_strhex(data):
	return '{0:02x}'.format(int.from_bytes(data, byteorder='big'))

if (len(sys.argv) <= 1):
	print("Tempoaray useage: parse.py a.out")
	sys.exit(1)
with open(sys.argv[1], "rb") as infile:
	file = infile.read()
	conv = 0
	start = 0
	skip = 4
	end = skip
	arch = check_magic(file[start:end])
	sum_ += 0x28
	print("arch:\t" + arch)

	# start of output table
	print("segment\tdec\t\thex\t\t\toffset\t\tbinja addr")


	start += skip
	end += skip
	print("text\t" + ret_int_hex_size(file[start:end]))
	

	start += skip
	end += skip
	print("data\t" + ret_int_hex_size(file[start:end]))
	

	start += skip
	end += skip
	print("bss\t\t" + ret_int_hex_size(file[start:end]))
	

	start += skip
	end += skip
	print("syms\t" + ret_int_hex_size(file[start:end]))
	

	start += skip
	end += skip
	entry_point = int.from_bytes(file[start:end], byteorder='big')
	
	#print("entry point:\t" + ret_int_hex_size(file[start:end]))
	start += skip
	end += skip
	if (arch == "68020"):
		print("spsz\t" + ret_int_hex_size(file[start:end]))
	
	start += skip
	end += skip
	print("pcsz\t" + ret_int_hex_size(file[start:end])) 
	print()

	print('Jumping to entry_point: 0x{0:08x}'.format(entry_point))
	#print(bytes_to_strhex(file[start:end]))

	if (arch == "amd64"):
		skip = 8
		start += skip
		md = Cs(CS_ARCH_X86, CS_MODE_64)
	elif (arch == "intel 386"):
		skip = 4
		md = Cs(CS_ARCH_X86, CS_MODE_32)
	elif (arch == "mips 3000 BE"):
		skip = 4
		md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN)
	elif (arch == "mips 3000 LE"):
		skip = 4
		md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
	elif (arch == "mips 4000 BE"):
		skip = 8
		md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS64 + CS_MODE_BIG_ENDIAN)
	elif (arch == "mips 4000 BE"):
		skip = 8
		md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS64 + CS_MODE_LITTLE_ENDIAN)
	elif (arch == "arm"):
		skip = 4
		md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
	elif (arch == "arm64"):
		skip = 8
		md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
	elif (arch == "powerpc"):
		skip = 4
		md = Cs(CS_ARCH_PPC, CS_MODE_32)
	elif (arch == "powerpc64"):
		skip = 8
		md = Cs(CS_ARCH_PPC, CS_MODE_64)
	elif (arch == "sparc"):
		skip = 4
		md = Cs(CS_ARCH_SPARC)

	start += 0x4
	#print(hex(start))
	#print(file[start:start+0x1])	
	for i in md.disasm(file[start:], entry_point):
		print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

	if (conv == 1):
		# start of elf
		with open("a.out.elf", "wb") as out:
			out.write(b"\x7FELF")				# magic
			
			if (skip == 8):
				out.write(b"\x02")				# 64bt
			else:
				out.write(b"\x01")
			
			if (arch == "amd64"):
				out.write(b"\x01")				# little or Big endian?
			
			out.write(b"\x01")					# Version of ELF
			
			if (arch == "amd64"):
				out.write(b"\x00")				# Linux

			out.write(b"\x00")					# ABI Version
			out.write(b"\x00" * 7)				# unused bytes
			out.write(b"\x00\x00")				# no relro
			if (arch == "amd64"):
				out.write(b"\x3E\x00")			# x86_64

			ver = struct.pack("I", 0x1)
			out.write(ver)						# Version of ELF again?

			ent = struct.pack("Q", entry_point)	# pack int to bytes
			out.write(ent)						# e_entry; entry_point (def wrong)

			prog_head = struct.pack("Q", 0x40)	# e_phoff; points to program header table

			out.write(b"\x00" * 8)				# e_shoff; points to section header table 

			if (arch == "amd64"):
				flag = struct.pack("I", 0x0)
				out.write(flag)					# e_flags = 0?

			if (arch == "amd64"):
				ehsize = struct.pack("H", 0x40)
				out.write(ehsize)				# e_ehsize contains size of header 64bit = 3e?

			phentsize = struct.pack("H", 0x40)
			out.write(phentsize)				# e_phentsize contains size of program header

			out.write(b"\x00\x00")				# e_phnum contains number of entries prog header

			out.write(b"\x00\x00")				# e_shentsize; size of a section header table entry

			out.write(b"\x00\x01")				# e_shnum; number of entries in the section header table

			out.write(b"\x00\x00")				# e_shstrndx; index of the section header table entry

			# start program header

			out.write(b"\x00\x00\x00\x00")		# p_type
			out.write(b"\x00\x00\x00\x00")		# p_flags

			if (arch == "amd64"):
				out.write(b"\x00" * 8)			# p_offset

			if (arch == "amd64"):
				out.write(b"\x00" * 4)			# p_vaddr		
				out.write(b"\x04\x00\x00\x00")	# p_vaddr

			if (arch == "amd64"):
				out.write(b"\x00" * 8)			# p_paddr N/A?

			if (arch == "amd64"):
				out.write(b"\x00" * 8)			# p_filesz

			if (arch == "amd64"):
				out.write(b"\x00" * 8)			# p_memz

			if (arch == "amd64"):
				out.write(b"\x00" * 8)			# p_align


'''
Contains the size of a program header table entry.
0x2C 	0x38 	2 	e_phnum 	Contains the number of entries in the program header table.
0x2E 	0x3A 	2 	e_shentsize 	Contains the size of a section header table entry.
0x30 	0x3C 	2 	e_shnum 	Contains the number of entries in the section header table.
0x32 	0x3E 	2 	e_shstrndx 	Contains index of the section header table entry that contains 
'''


	
