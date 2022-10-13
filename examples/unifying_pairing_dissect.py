from whad.scapy.layers.esb import *
from whad.scapy.layers.unifying import *

bind()
pr1 = ESB_Hdr(bytes.fromhex("aabb0adca57558302f80dbf4cbe2ad042026820100a380000000000003d19100"))
pr2 = ESB_Hdr(bytes.fromhex("aabb0adca57558300f80cd85482137844404020080838000000000007ad17d80"))
pr3 = ESB_Hdr(bytes.fromhex("aa9b0a90426f5b302f81730ef3bb9e44fd980f20000004800000000043b30700"))
pr4 = ESB_Hdr(bytes.fromhex("aa9b0a90426f5b300f817b1f59289e44fd980f200000048000000000788a8c80"))
pr5 = ESB_Hdr(bytes.fromhex("aa9b0a90427659002f818084a59a18181028363ab98000000000000078e45580"))
for i in (pr1, pr2, pr3, pr4, pr5):
    i.show()
