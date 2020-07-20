all: dma

dma: dma.p4
	p4c-bm2-ss --arch v1model -o dma.json \
		--p4runtime-files dma-p4info.txt \
		dma.p4