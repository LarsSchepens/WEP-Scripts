import os, sys, time

msg = input("Press Enter when you have retrieved at least 30k packages")
os.system("ls")
capture_file = input("Input your .cap file:")
cmd = "aircrack-ng %s" %capture_file
os.system(cmd)



