all: univmon

univmon: univmon.p4
	p4c-bm2-ss --arch v1model -o univmon.json \
		--p4runtime-file univmon.p4info --p4runtime-format text \
		univmon.p4