#!/usr/bin/python
#
import struct
import sys

if(len(sys.argv) != 2):
    print "Wrong syntax"
    print "Syntax: "+ sys.argv[0] +" <filename>"
    exit()

pe = open(sys.argv[1],"rb").read()

BYTE = 0x01
WORD = 0x02
DWORD = 0x04
sec_header = 0xF8
sec_header_ind = 0

print "*"*20 + "DOS MZ HEADER" + "*"*20
dir_PE = struct.unpack("<I",pe[0x3c:0x3c+4])[0]
print "Direccion PE: " + str(hex(dir_PE))

print "*"*20 + "PE HEADER" + "*"*20
signature = struct.unpack("<I",pe[dir_PE:dir_PE+DWORD])[0]
print "Signature: " + str(hex(signature))
machine = struct.unpack("<H",pe[dir_PE+0x04:dir_PE+0x04+WORD])[0]
print "Machine: " + str(hex(machine))
num_secciones = struct.unpack("<H",pe[dir_PE+0x06:dir_PE+0x06+WORD])[0]
print "Numero de Secciones: " + str(hex(num_secciones))

print "*"*20 + "OPTIONAL HEADER" + "*"*20
magic = struct.unpack("<H",pe[dir_PE+0x18:dir_PE+0x18+WORD])[0]
print "Magic: " + str(hex(magic))
size_code = struct.unpack("<I",pe[dir_PE+0x1C:dir_PE+0x1C+DWORD])[0]
print "Size of Code: " + str(hex(size_code))
entry_point = struct.unpack("<I",pe[dir_PE+0x28:dir_PE+0x28+DWORD])[0]
print "Entry Point: " + str(hex(entry_point))

print "*"*20 + "SECTION HEADER" + "*"*20
for i in range(4):
    index = 0x28 * i
    name = pe[dir_PE+sec_header+index:dir_PE+sec_header+index+0x08]
    if ".text" in name and ".textbss" not in name:
        print "Name: " + str(name)
        sec_header_ind = sec_header + index
virtual_size = struct.unpack("<I",pe[dir_PE+sec_header_ind+0x08:dir_PE+sec_header_ind+0x08+DWORD])[0]
print "Virtual Size: " + str(hex(virtual_size))
virtual_addr = struct.unpack("<I",pe[dir_PE+sec_header_ind+0x0C:dir_PE+sec_header_ind+0x0C+DWORD])[0]
print "Virtual Address: " + str(hex(virtual_addr))
pointerToRawData = struct.unpack("<I",pe[dir_PE+sec_header_ind+0x14:dir_PE+sec_header_ind+0x14+DWORD])[0]
print "Pointer to Raw Data: " + str(hex(pointerToRawData))

print "*"*20 + "OTHER CALCULATION" + "*"*20
mem_fisica = entry_point - virtual_addr + pointerToRawData
print "Memoria Fisica: " + str(hex(mem_fisica))
