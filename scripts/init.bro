###
## This is the S7comm plugin's event handler script
## Author: Gyorgy Miru
## Date: 2015.12.17.
## Version: 0.3

module S7comm;
@load ./consts


export {
    redef enum Log::ID += { LOG1, LOG2, LOG3, };
    
    type InfoIso: record {
		## Time when the command was sent.
		ts:               time        &log;
		## Unique ID for the connection.
		uid:              string      &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:               conn_id     &log;
		## COTP msg type.
		msg:             string      &log;
    };

    type InfoS7comm: record {
		## Time when the command was sent.
		ts:               time        &log;
		## Unique ID for the connection.
		uid:              string      &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:               conn_id     &log;
		## the s7 message type
		msgtype:          string      &log;
		## the s7 message type number
		msgtypenum:       count       ;
        ## function mode for UD
        funcmode:         string      &optional &log;
        ## function mode num fo ud
        funcmodenum:      count       &optional;
		## the function number of the msg
		functypenum:      count       ;
		## the function type of the msg
		functype:         string      &log;
        ## subfunction for ud
        subfunctypenum:    count       &optional;
        ## subfunction str fo ud
        subfunctype:       string      &optional &log;
		##
		error:             count       &log;
    };

    type InfoS7data: record {
		## Time when the command was sent.
		ts:               time        &log;
		## Unique ID for the connection.
		uid:              string      &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:               conn_id     &log;
		## memory area
		area:             string      &log;
		## memory areanum
		areanum:          count      ;
		## the function type of the msg
		dbnum:            count      &log;
		## s7 type
		s7type: 		  string     &log;
		## s7 typenum
		s7typenum:        count      ;
		## s7 address
		address:          count      &log;
		## s7 signed data
		sdata:            int        &optional &log;
		## s7 unsigned data
		udata:            count      &optional &log;
		## s7 real data
		ddata:            double     &optional &log;
		isread:           bool       &log;

    };

    global log_iso_cotp: event(rec: InfoIso);

    global log_s7comm: event(rec: InfoS7comm);

    global log_s7data: event(rec: InfoS7data);
    
    }

redef record connection += {
    iso_cotp: InfoIso &optional;
    s7comm: InfoS7comm &optional;
    s7data: InfoS7data &optional;
    };

const ports = { 102/tcp };
# redef likely_server_ports += { ports };

#  ../lib/bif/s7comm.bif


event bro_init() &priority=5
	{
	Log::create_stream(S7comm::LOG1, [$columns=InfoIso, $ev=log_iso_cotp, $path="iso_cotp"]);
	Log::create_stream(S7comm::LOG2, [$columns=InfoS7comm, $ev=log_s7comm, $path="s7comm"]);
	Log::create_stream(S7comm::LOG3, [$columns=InfoS7data, $ev=log_s7data, $path="s7data"]);
	Analyzer::register_for_ports(Analyzer::ANALYZER_S7COMM, ports);
	}

event iso_cotp_packet(c: connection, msg: string, cdt: count) &priority=5
{
    local s: InfoIso;
    s$ts=network_time();
    s$uid=c$uid;
    s$id=c$id;
    c$iso_cotp=s;
    
    c$iso_cotp$msg=msg;
    Log::write(S7comm::LOG1, c$iso_cotp);
}

event siemenss7_packet(c: connection, msgtype: count, functype: count, errno: count) &priority=5
{
	local s: InfoS7comm;
    s$ts=network_time();
    s$uid=c$uid;
    s$id=c$id;
    s$msgtype=s7msg_types[msgtype];
    s$msgtypenum=msgtype;
    s$functype=s7func_types[functype];
    s$functypenum=functype;
    s$error=errno;

    c$s7comm=s;
    
    Log::write(S7comm::LOG2, c$s7comm);
}

event siemenss7_ud_packet(c: connection, msgtype: count, functionmode: count, functiontype: count, subfunction: count, errno: count) &priority=5
{
    local s: InfoS7comm;
    s$ts=network_time();
    s$uid=c$uid;
    s$id=c$id;
    s$msgtype=s7msg_types[msgtype];
    s$msgtypenum=msgtype;
    s$funcmodenum=functionmode;
    s$funcmode=s7udfunc_modes[functionmode];
    s$functype=s7udfunc_types[functiontype];
    s$functypenum=functiontype;
    s$subfunctypenum=subfunction;
    
    switch subfunction
    {
        case 1:
            s$subfunctype=s7udsubfunc_type_prog[subfunction];
            break;
        case 2:
            s$subfunctype=s7udsubfunc_type_cyclic[subfunction];
            break;
        case 3:
            s$subfunctype=s7udsubfunc_type_block[subfunction];
            break;
        case 4:
            s$subfunctype=s7udsubfunc_type_cpu[subfunction];
            break;
        case 5:
            s$subfunctype=s7udsubfunc_type_sec[subfunction];
            break;
        case 6:
            s$subfunctype=s7udsubfunc_type_time[subfunction];
            break;
        default:
            s$subfunctype = fmt("unknown-%d", subfunction);
            break;
    }
    
    s$error=errno;

    c$s7comm=s;
    
    Log::write(S7comm::LOG2, c$s7comm);

}

event siemenss7_read_data_unsigned(c: connection, area: count, db: count, s7type: count, address: count, data: count) &priority=5
{
	local s: InfoS7data;
    s$ts=network_time();
    s$uid=c$uid;
    s$id=c$id;
    s$area=s7area_types[area];
    s$areanum=area;
    s$dbnum=db;
    s$s7type=s7type_types[s7type];
    s$s7typenum=s7type;
    s$address=address;
    s$udata=data;
    s$isread=T;

    c$s7data=s;

#    print "This is siemenss7_read_data_unsigned"; #or siemenss7_read_data_unsigned
#    print c$s7data;
    
    Log::write(S7comm::LOG3, c$s7data);
}

event siemenss7_read_data_signed(c: connection, area: count, db: count, s7type: count, address: count, data: int) &priority=5
{
	local s: InfoS7data;
    s$ts=network_time();
    s$uid=c$uid;
    s$id=c$id;
    s$area=s7area_types[area];
    s$areanum=area;
    s$dbnum=db;
    s$s7type=s7type_types[s7type];
    s$s7typenum=s7type;
    s$address=address;
    s$sdata=data;
    s$isread=T;

    c$s7data=s;
    
#    print "This is siemenss7_read_data_signed"; #or siemenss7_read_data_unsigned
#    print c$s7data;

    Log::write(S7comm::LOG3, c$s7data);
}

event siemenss7_read_data_real(c: connection, area: count, db: count, s7type: count, address: count, data: double) &priority=5
{
	local s: InfoS7data;
    s$ts=network_time();
    s$uid=c$uid;
    s$id=c$id;
    s$area=s7area_types[area];
    s$areanum=area;
    s$dbnum=db;
    s$s7type=s7type_types[s7type];
    s$s7typenum=s7type;
    s$address=address;
    s$ddata=data;
    s$isread=T;

    c$s7data=s;
    
#    print "This is siemenss7_read_data_real"; #or siemenss7_read_data_unsigned
#    print c$s7data;

    Log::write(S7comm::LOG3, c$s7data);
}

event siemenss7_write_data_unsigned(c: connection, area: count, db: count, s7type: count, address: count, data: count) &priority=5
{
	local s: InfoS7data;
    s$ts=network_time();
    s$uid=c$uid;
    s$id=c$id;
    s$area=s7area_types[area];
    s$areanum=area;
    s$dbnum=db;
    s$s7type=s7type_types[s7type];
    s$s7typenum=s7type;
    s$address=address;
    s$udata=data;
    s$isread=F;

    c$s7data=s;
    
#    print "This is siemenss7_write_data_unsigned"; #or siemenss7_read_data_unsigned
#    print c$s7data;

    Log::write(S7comm::LOG3, c$s7data);
}

event siemenss7_write_data_signed(c: connection, area: count, db: count, s7type: count, address: count, data: int) &priority=5
{
	local s: InfoS7data;
    s$ts=network_time();
    s$uid=c$uid;
    s$id=c$id;
    s$area=s7area_types[area];
    s$areanum=area;
    s$dbnum=db;
    s$s7type=s7type_types[s7type];
    s$s7typenum=s7type;
    s$address=address;
    s$sdata=data;
    s$isread=F;

    c$s7data=s;
    
#    print "This is siemenss7_write_data_signed"; #or siemenss7_read_data_unsigned
#    print c$s7data;

    Log::write(S7comm::LOG3, c$s7data);
}

event siemenss7_write_data_real(c: connection, area: count, db: count, s7type: count, address: count, data: double) &priority=5
{
	local s: InfoS7data;
    s$ts=network_time();
    s$uid=c$uid;
    s$id=c$id;
    s$area=s7area_types[area];
    s$areanum=area;
    s$dbnum=db;
    s$s7type=s7type_types[s7type];
    s$s7typenum=s7type;
    s$address=address;
    s$ddata=data;
    s$isread=F;

    c$s7data=s;
    
#    print "This is siemenss7_write_data_real"; #or siemenss7_read_data_unsigned
#    print c$s7data;

    Log::write(S7comm::LOG3, c$s7data);
}
