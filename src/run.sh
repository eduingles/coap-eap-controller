#/bin/bash!
killall mote
killall mote

CONTADOR=5683
for i in `seq 1 10`;
do
	 #CONTADOR=$((CONTADOR+$i))
#	echo $((CONTADOR+$i+1000))
#	./mota2 -p $((CONTADOR+$i)) -P $((CONTADOR+$i+1000)) &
	./mote ::1 $((CONTADOR+$i)) aaaa::1 $((CONTADOR)) &
	usleep .1
done    


#./mota2 -p 7001 -P 8001 &
#./mota2 -p 7002 -P 8002 &
#./mota2 -p 7003 -P 8003 &
#./mota2 -p 7004 -P 8004 &
#./mota2 -p 7005 -P 8005 &
#./mota2 -p 7006 -P 8006 &
#./mota2 -p 7007 -P 8007 &
#./mota2 -p 7008 -P 8008 &
#./mota2 -p 7009 -P 8009 &
