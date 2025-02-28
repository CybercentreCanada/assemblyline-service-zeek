##! Our version of /usr/share/bro/base/init-default.bro

##! This script loads everything in the base/ script directory.  If you want
##! to run Bro without all of these scripts loaded by default, you can use
##! the ``-b`` (``--bare-mode``) command line argument.  You can also copy the
##! "@load" lines from this script to your own script to load only the scripts
##! that you actually want.

@load base/utils/site
@load base/utils/active-http
@load base/utils/addrs
@load base/utils/conn-ids
@load base/utils/dir
@load base/utils/directions-and-hosts
@load base/utils/exec
@load base/utils/files
@load base/utils/numbers
@load base/utils/paths
@load base/utils/patterns
@load base/utils/queue
@load base/utils/strings
@load base/utils/thresholds
@load base/utils/time
@load base/utils/urls

# This has some deep interplay between types and BiFs so it's
# loaded in base/init-bare.bro
#@load base/frameworks/logging
@load base/frameworks/notice
@load base/frameworks/analyzer
#deprecated as of 6.1
#@load base/frameworks/dpd
@load base/frameworks/signatures
@load base/frameworks/packet-filter
@load base/frameworks/software
#@load base/frameworks/communication
#this might replace communication
#@load base/frameworks/cluster
@load base/frameworks/control
@load base/frameworks/cluster
@load base/frameworks/intel
@load base/frameworks/reporter
@load base/frameworks/sumstats
@load base/frameworks/tunnels

@load base/protocols/conn
@load base/protocols/dhcp
@load base/protocols/dnp3
@load base/protocols/dns
@load base/protocols/ftp
@load base/protocols/http
@load base/protocols/irc
@load base/protocols/krb
@load base/protocols/modbus
@load base/protocols/mysql
@load base/protocols/pop3
@load base/protocols/radius
@load base/protocols/rdp
@load base/protocols/sip
@load base/protocols/snmp
@load base/protocols/smtp
@load base/protocols/socks
@load base/protocols/ssh
@load base/protocols/ssl
@load base/protocols/syslog
@load base/protocols/tunnels

@load base/files/pe
@load base/files/hash
@load base/files/extract
#removed https://community.zeek.org/t/removal-of-barnyard2-and-unified2-support/6652
#@load base/files/unified2
@load base/files/x509
@load base/misc/find-filtered-trace

@load policy/frameworks/files/extract-all-files.zeek

##! We do not need this file
##@load base/misc/find-checksum-offloading



##! We redefine conn.log
redef record Conn::Info += {
	        src_ip: addr &log &default = 0.0.0.0;
	        src_port: port &log &default = 0/icmp;
	        dst_ip: addr &log &default = 0.0.0.0;
	        dst_port: port &log &default = 0/icmp;
	        client_timestamp: time &log &optional;
	        client_info:string &log &optional;
	        client_flags:string &log &optional;
	        client_seq:int &log &optional;
	        client_ack:int &log &optional;
	        client_len:int &log &optional;
	        client_payload:string &log &optional;
	        server_timestamp: time &log &optional;
	        server_info:string &log &optional;
	        server_flags:string &log &optional;
	        server_seq:int &log &optional;
	        server_ack:int &log &optional;
	        server_len:int &log &optional;
	        server_payload:string &log &optional;
        };

        type Info_Ack: record {
                timestamp:time &log;
                information: string &log;
                flags: string &log;
                seq: count &log;
                ack: count &log;
                len: count &log;
                payload: string &log;

        };

        type Info_Ack_tmp: record {
                timestamp:time;
                information: string;
                flags: string;
                seq: count;
                ack: count;
                len: count;
                payload: string;
        };

        global proto : string;
        global source_ip : addr;
        global source_port :port;
        global dest_ip : addr;
        global dest_port: port;
        global ack_table: table[string] of Info_Ack_tmp;
        global packet_count_table: table[string] of count;
        const PACKET_KEEP_COUNT = 5;

# This event create the information of the first packet of the tcp sessions.
# This info will be saved in the conn logs, when the session is terminated.

event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string)
   {

        if (len > 0) {

                local info : string;
                local tmp_0: string;
                local tmp_1: string;
				local tmp_payload: string;
                local direction: string;
                local tmp_pack_c: count;

                if (is_orig) {
                        direction = "Incoming";
                }
                else {
                        direction = "Outgoing";
                }

                tmp_0 = fmt("%s_%s_%s_%s_%s",c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p,direction);
                tmp_1 = subst_string(tmp_0,".","_");
                info = subst_string(tmp_1,"\/","_");

                if (!(info in ack_table)) {
                        ack_table [info] = [$timestamp=network_time(), $information=info,$flags=flags,$seq=seq,$ack=ack,$len=len,$payload=payload];
                        packet_count_table[info] = 1;
                } else if (packet_count_table[info] < PACKET_KEEP_COUNT) {
                	tmp_payload = ack_table[info]$payload;
                	ack_table[info]$payload = tmp_payload + payload;
                	tmp_pack_c = packet_count_table[info];
                	packet_count_table[info] = tmp_pack_c + 1;
                }
        }
}

# With this event, we generate the connection log information with all of the info required.
# We also add country, city GEO info and ASN for both source and destination.
# This added info will also be saved in the conn.log.
event connection_state_remove(c:connection)
        {

        c$conn$src_ip   = c$id$orig_h;
        c$conn$src_port = c$id$orig_p ;
        c$conn$dst_ip   = c$id$resp_h ;
        c$conn$dst_port = c$id$resp_p ;

        local tmp_proto = fmt ("%s",c$id$orig_p);
        proto = split_string(tmp_proto,/\//)[1];

        if ( proto == "tcp")
                {

                local info_incoming : string;
                local info_outgoing : string;
                local tmp_0: string;
                local tmp_1: string;

                local direction: string;

                direction = "Incoming";
                tmp_0 = fmt("%s_%s_%s_%s_%s", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p, direction);
                tmp_1 = subst_string(tmp_0,".","_");
                info_incoming = subst_string(tmp_1,"\/","_");

                direction = "Outgoing";
                tmp_0 = fmt("%s_%s_%s_%s_%s", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p, direction);
                tmp_1 = subst_string(tmp_0,".","_");
                info_outgoing = subst_string(tmp_1,"\/","_");

                if (info_incoming in ack_table)
                        {
                        c$conn$client_timestamp= ack_table[info_incoming]$timestamp;
                        c$conn$client_info= ack_table[info_incoming]$information;
                        c$conn$client_flags = ack_table[info_incoming]$flags;
                        c$conn$client_seq = ack_table[info_incoming]$seq;
                        c$conn$client_ack = ack_table[info_incoming]$ack;
                        c$conn$client_len = ack_table[info_incoming]$len;
                        c$conn$client_payload = ack_table[info_incoming]$payload;
                        }
                if (info_outgoing in ack_table)
                        {
                        c$conn$server_timestamp= ack_table[info_outgoing]$timestamp;
                        c$conn$server_info = ack_table[info_outgoing]$information;
                        c$conn$server_flags = ack_table[info_outgoing]$flags;
                        c$conn$server_seq = ack_table[info_outgoing]$seq;
                        c$conn$server_ack = ack_table[info_outgoing]$ack;
                        c$conn$server_len = ack_table[info_outgoing]$len;
                        c$conn$server_payload = ack_table[info_outgoing]$payload;
                        }
                }
        }
##! This was in the original script

redef FilteredTraceDetection::enable = F;

##! This is for the json format

redef LogAscii::use_json = T;
