all: flowstats

flowstats: flowstats.p4
	p4c-bm2-ss --arch v1model -o flowstats.json \
		--p4runtime-file flowstats.p4info --p4runtime-format text \
		flowstats.p4