all: univmon

univmon: univmon.p4
	p4c-bm2-ss --arch v1model -o univmon.json \
		--p4runtime-files univmon-p4info.txt \
		univmon.p4