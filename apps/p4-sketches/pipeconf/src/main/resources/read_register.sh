#!/bin/bash

THIS_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

timestamp() {
   	date +"%Y-%m-%d %H:%M:%S:%3N" 
}

source ~/tutorials/env.sh

CLI_PATH=$BMV2_PATH/targets/simple_switch/sswitch_CLI
HASHLIST_PATH=/home/shinkirou/Documents/thesis-flow-stats/hashlist.txt
JSON_PATH=~/onos/apps/p4-sketches/pipeconf/src/main/resources/flowstats.json
OUTPUT_PATH=/home/shinkirou/Documents/thesis-flow-stats/
FLOWS_PATH=/home/shinkirou/Documents/thesis-flow-stats/flows.txt

OUTPUT_FILE=$OUTPUT_PATH/output-`date +%Y%m%d-%H%M%S`.txt
FLOWS_SKETCH_FILE=$OUTPUT_PATH/sketches-`date +%Y%m%d-%H%M%S`.txt

while read p; 
do
	# FLOWS_MATCH_SRC_MAC_TEMP=$(echo "$p" | grep -P -o '\w+:\w+:\w+:\w+:\w+:\w+,\w+:')
	# FLOWS_MATCH_SRC_MAC=$(echo "${FLOWS_MATCH_SRC_MAC_TEMP::-5}")
	# FLOWS_MATCH_DST_MAC_TEMP=$(echo "$p" | grep -P -o '\w+:\w+:\w+:\w+:\w+:\w+,\w+\.')
	# FLOWS_MATCH_DST_MAC=$(echo "${FLOWS_MATCH_DST_MAC_TEMP::-6}")
	FLOWS_MATCH_SRC_IP_TEMP=$(echo "$p" | grep -P -o '\d+\.\d+\.\d+\.\d+,')
	FLOWS_MATCH_SRC_IP=$(echo "${FLOWS_MATCH_SRC_IP_TEMP::-1}")
	FLOWS_MATCH_DST_IP=$(echo "$p" | grep -P -o '\d+\.\d+\.\d+\.\d+$')
	if [ -z "$FLOWS_MATCH_SRC_IP" ] || [ -z "$FLOWS_MATCH_DST_IP" ]
	then
		continue
	fi
	while read q;
	do
		# HASH_MATCH_SRC_MAC_TEMP=$(echo "$q" | grep -P -o '\w+:\w+:\w+:\w+:\w+:\w+,\w+:')
		# HASH_MATCH_SRC_MAC=$(echo "${HASH_MATCH_SRC_MAC_TEMP::-5}")
		# HASH_MATCH_DST_MAC_TEMP=$(echo "$q" | grep -P -o '\w+:\w+:\w+:\w+:\w+:\w+,\w+\.')
		# HASH_MATCH_DST_MAC=$(echo "${HASH_MATCH_DST_MAC_TEMP::-6}")
		HASH_MATCH_SRC_IP_TEMP=$(echo "$q" | grep -P -o '\d+\.\d+\.\d+\.\d+,')
		HASH_MATCH_SRC_IP=$(echo "${HASH_MATCH_SRC_IP_TEMP::-1}")
		HASH_MATCH_DST_IP=$(echo "$q" | grep -P -o '\d+\.\d+\.\d+\.\d+$')
		MATCH_CM_HASH=$(echo "$q" | grep -P -o '^\w+')
		MATCH_BM_HASH_TEMP=$(echo "$q" | grep -P -o '\w+ d')
		MATCH_BM_HASH=$(echo "${MATCH_BM_HASH_TEMP::-2}")
		if 	[ "$FLOWS_MATCH_SRC_IP" == "$HASH_MATCH_SRC_IP" ] &&
			[ "$FLOWS_MATCH_DST_IP" == "$HASH_MATCH_DST_IP" ]
		then
			FLOW_SKETCH=$p 
			FLOW_SKETCH+=" "
			SKETCH_CM=$(echo "register_read count_register_final $MATCH_CM_HASH" | $CLI_PATH $JSON_PATH 1 | grep -P -o '(\w+)$')
			SKETCH_BM=$(echo "register_read bitmap_register $MATCH_BM_HASH" | $CLI_PATH $JSON_PATH 1 | grep -P -o '(\w+)$')
			echo -n "$FLOW_SKETCH" >> $FLOWS_SKETCH_FILE
			echo -n "$SKETCH_CM" >> $FLOWS_SKETCH_FILE
			echo -n " " >> $FLOWS_SKETCH_FILE
			echo "$SKETCH_BM" >> $FLOWS_SKETCH_FILE	
			break	
		fi
	done < $HASHLIST_PATH
done < $FLOWS_PATH

exit