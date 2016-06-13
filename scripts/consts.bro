## This script contains the exported S7 protocol constants
## Author: Gyorgy Miru
## Date: 2015.11.28
## Version: 0.1

module S7comm;

export {
	const s7msg_types = {
		[0x01] = "S7 ROSCTR JOB",
		[0x02] = "S7 ROSCTR ACK",
		[0x03] = "S7 ROSCTR ACK_DATA",
		[0x07] = "S7 ROSCTR USERDATA",
	} &default=function(i: count):string { return fmt("unknown-%d", i); } &redef;

	const s7func_types = {
		[0x00] = "CPU services",
		[0xF0] = "Setup communication",
		[0x04] = "Read Var",
		[0x05] = "Write Var",
		[0x1A] = "Request download",
		[0x1B] = "Download block",
		[0x1C] = "Download ended",
		[0x1D] = "Start upload",
		[0x1E] = "Upload",
		[0x1F] = "End upload",
		[0x28] = "PLC Control",
		[0x29] = "PLC Stop",
	} &default=function(i: count):string { return fmt("unknown-%d", i); } &redef;

	const s7area_types = {
		[0x03] = "System info of 200 family",
		[0x05] = "System flags of 200 family",
		[0x06] = "Analog inputs of 200 family",
		[0x07] = "Analog outputs of 200 family",
        
        [28] = "C (S7 counter)",
		[29] = "T (S7 timer)",
		[30] = "IEC counters (200 family)",
		[31] = "IEC timers (200 family)",

		[0x80] = "P",
		[0x81] = "I",
		[0x82] = "Q",
		[0x83] = "M",
		[0x84] = "DB",
		[0x85] = "DBI",
		[0x86] = "L",
		[0x87] = "V (Unknown yet)",
	} &default=function(i: count):string { return fmt("unknown-%d", i); } &redef;

	const s7type_types = {
		[1] = "BIT",
		[2] = "BYTE",
		[3] = "CHAR",

		[4] = "WORD",
		[5] = "INT",

		[6] = "DWORD",
		[7] = "DINT",
		[8] = "REAL",

		[9] = "DATE",
		[10] = "TOD",
		[11] = "TIME",
		[12] = "S5TIME",
		[15] = "DATE_AND_TIME",

		[28] = "COUNTER",
		[29] = "TIMER",
		[30] = "IEC TIMER",
		[31] = "IEC COUNTER",
		[32] = "HS COUNTER",

	} &default=function(i: count):string { return fmt("unknown-%d", i); } &redef;

    const s7udfunc_modes = {
        [0] = "UD PUSH",
        [4] = "UD RESUEST",
        [8] = "UD RESPONSE",
	} &default=function(i: count):string { return fmt("unknown-%d", i); } &redef;

    const s7udfunc_types = {
        [1] = "UD Programming",
        [2] = "UD Cyclic",
        [3] = "UD Block",
        [4] = "UD CPU",
        [5] = "UD Security",
        [6] = "UD Time",    
	} &default=function(i: count):string { return fmt("unknown-%d", i); } &redef;

    const s7udsubfunc_type_prog = {
        [0x14] = "Vartab Request",
        [0x04] = "Vartab Response",
        [0x01] = "Request Diag Data",
        [0x02] = "VAT1",
        [0x0c] = "Erase",
        [0x0e] = "Read Diag Data",
        [0x0f] = "Remove Diag Data",
        [0x10] = "Force",
        [0x13] = "Request Diag Data2",
	} &default=function(i: count):string { return fmt("unknown-%d", i); } &redef;

    const s7udsubfunc_type_cyclic = {
        [0x01] = "Memory",
        [0x04] = "Unsubscribe",
	} &default=function(i: count):string { return fmt("unknown-%d", i); } &redef;
    
    const s7udsubfunc_type_block = {
        [0x01] = "List",
        [0x02] = "List Type",
        [0x03] = "Block Info",
	} &default=function(i: count):string { return fmt("unknown-%d", i); } &redef;

    const s7udsubfunc_type_sec = {
        [0x01] = "PLC Password",
	} &default=function(i: count):string { return fmt("unknown-%d", i); } &redef;

    const s7udsubfunc_type_time = {
        [0x01] = "Read",
        [0x02] = "Set",
        [0x03] = "Readf",
        [0x04] = "Set2",
	} &default=function(i: count):string { return fmt("unknown-%d", i); } &redef;
    
    const s7udsubfunc_type_cpu = {
        [1] = "Read SZL",
        [2] = "Message Service",
        [3] = "STOP",
        [4] = "ALARM indication",
        [5] = "ALARM initiate",
        [6] = "ALARM Ack1",    
        [7] = "ALARM Ack2",    
	} &default=function(i: count):string { return fmt("unknown-%d", i); } &redef;

}
