import os
from subprocess import Popen, PIPE

#run_tcpdump
def run_tcpdump(target_name, sec):
	os.system("adb -s {0} shell push ".format(target_name))
	
	#Add remount code 
	os.system("adb -s {0} shell su -c \"chmod 777 /system/xbin/tcpdump\"".format(target_name))	#chmod tcp dump
	os.system("adb -s {0} shell su -c /system/xbin/tcpdump & > out.pcap".format(target_name))	#start tcp_dump
	
	time.sleep(sec)

	#kill tcpdump
	tcpdump_kill1=Popen(['adb', '-s', target_name, 'shell', 'ps'], stdout=PIPE)
	tcpdump_kill2=Popen(['grep', tcpdump], stdin=tcpdump_kill1.stdout, stdout=PIPE)
	tcpdump_kill3=Popen(['awk', '\'{print $2}\''], stdin=tcpdump_kill2.stdout, stdout=PIPE)
	
	tcpdump_kill1.stdout.kill()
	tcpdump_kill2.stdout.kill()
	tcpdump_output=tcpdump_kill3.stdout
	
	#pull out.pcap
	os.system("adb -s {0} pull ".format(target_name))
	os.system("adb -s {0} shell su -c \"kill -9 {1}\"".format(target_name, tcpdump_output[0]))
	os.system("adb -s {0} shell su -c \"rm /system/xbin/tcpdump\"".format(target_name))
	

	
	
