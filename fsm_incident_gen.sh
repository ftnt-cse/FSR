#! /bin/bash
for x in {1..20}
do
	echo '.'
	j=$(($RANDOM % 244))
	k=$(($RANDOM % 244))

	echo '<185>'`date +"%b %d %T"`' date='`date +"%F"`' time='`date +"%T"`' devname=FG240D3913800441 devid=FG240D3913800441 logid=0419016384 type=utm subtype=ips eventtype=signature level=alert vd=root severity=critical srcip='`expr $k + 5`'.102.'$j'.227 srccountry=""India"" dstip=192.168.'$j'.'$k' srcintf=""wan1"" dstintf=""HoneyZone"" policyid=6 sessionid=51982011 action=detected proto=6 service=""SMB"" attack=""MS.DCERPC.netAPI32.Buffer.Overflow"" srcport=2963 dstport=445 direction=outgoing attackid=15995 profile=""Honeydrive_monitor"" ref=""http://www.fortinet.com/ids/VID15995"" incidentserialno=2022573626 msg=""netbios: MS.DCERPC.netAPI32.Buffer.Overflow' | nc 10.0.1.5 514
	sleep 120
done
