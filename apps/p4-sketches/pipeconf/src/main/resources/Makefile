all: flowstats

flowstats: flowstats.p4
	p4c-bm2-ss --arch v1model -o flowstats.json \
		--p4runtime-files flowstats.p4info.txt \
		flowstats.p4