var app = app || {};
app.modules = app.modules || {};

var tables = function() {
	var self = this;
	self.t = app.client.tables;
	self.t.fn._init();
}

app.modules['tables'] = tables;


app.client.tables.summary.fn = {

    update: function(y) {

		var requester = y.requester;
		var flow = y.flow;

        var summary = app.client.tables.summary;
        var sum = app.client.tables.summary;

        if(sum.data[flow.iface] == undefined) {
            sum.data[flow.iface] = _.clone(app.DEFS.SUMMARY);
            sum.data[flow.iface].iface = flow.iface;
            sum.data[flow.iface].tot = flow.total_bytes;
            sum.data[flow.iface].ts_b = flow.ts_b;
        }

        sum = sum.data[flow.iface];

        switch(flow.proto) {
            case "ICMP": {
                sum.icmp = sum.icmp + flow.bytes;
                break;
            }
            case "TCP": {
                sum.tcp = sum.tcp + flow.bytes;
                break;
            }
            case "UDP": {
                sum.udp = sum.udp + flow.bytes;
                break;
            }
            default: {
                break;
            }
        }

        sum.tot = sum.tot + flow.bytes;

        /*
         * Timestamp time..
         */
        if(sum.ts_b > flow.ts_b) {
            sum.ts_b = flow.ts_b;
        }
        if(sum.ts_e < flow.ts_e) {
            sum.ts_e = flow.ts_e;
        }


        sum.ts_tot = ((sum.ts_e - sum.ts_b) / 1000);

        var key = flow.iface;
        var tr = summary.table.fnFindCellRowIndexes(key, 0);
        if(tr.length == 0) {
            summary.table.fnAddData(
                [ key, sum.tot, sum.tcp, sum.udp, sum.icmp, sum.ts_tot.toFixed(0), sum.ts_b, sum.ts_e ]
            , requester > 0 ? false : true);
        } else {
            var row = summary.table.fnGetData(tr[0]);
            row[1] = sum.tot;
            row[2] = sum.tcp;
            row[3] = sum.udp;
            row[4] = sum.icmp;
            row[5] = sum.ts_tot.toFixed(0);
            row[6] = sum.ts_b;
            row[7] = sum.ts_e;
            summary.table.fnUpdate(row, tr[0], undefined, requester > 0 ? false : true);
        }

if(requester == 2) { 
	app.client.tables.summary.table.fnStandingRedraw();
}

        /*
         * update summary
         */
        app.client.charts.summary.fn.handle.update(sum);
    },



}


app.client.tables.fn = {


    make_table_key: function(x) {
        /* x = obj.key_str */
        var new_key;
//        new_key = x.replace(/,/g, '_');
//        new_key = new_key.replace(/\./g, '-');
		new_key = x;

        return new_key;
    },

    reverse_table_key: function(x) {
        /* x = table tbody td id string, return obj.key_str */
        var orig_key;
//        orig_key = x.replace(/_/g, ',');
//        orig_key = orig_key.replace(/-/g, '\.');
		orig_key = x;

        return orig_key;
    },

    make_toptalk_key: function(x) {
        /* Arg is flow */
//        var new_key = x.iface + "_" + x.src;
//        new_key = new_key.replace(/\./g, '_');
		var new_key = x.iface + "_" + x.src;
        return new_key;
    },


    make_key: function(x) {
	/* BAH FU*KING HUMBUG */
        /* Arg is packet{} */
        var packet = x;

		if(app.client.options.type == app.DEFS.TYPE.CONDENSE && app.client.options.type_sub == app.DEFS.TYPE.CONDENSE_SMART && (packet.proto == "TCP" || packet.proto == "UDP")) {
			if(packet.dport < packet.sport) {
				packet.sport = 0;
			}
			else { /* packet.dport > packet.sport*/
				var ta;

				ta = packet.dst;
				tb = packet.dst_addr;
				packet.dst = packet.src;
				packet.dst_addr = packet.src_addr;
				packet.dport = packet.sport;
				packet.src = ta;
				packet.src_addr = tb;
				packet.sport = 0;
			}

			packet.first_source = packet.src;
		}

        var key = _.clone(app.DEFS.KEY);

        if(packet.src_addr < packet.dst_addr) {
            key.left = packet.src;
            key.right = packet.dst;
            key.left_port = packet.sport;
            key.right_port = packet.dport;

        }
        else {
            key.left = packet.dst;
            key.right = packet.src;
            key.left_port = packet.dport;
            key.right_port = packet.sport;
        }

        key.iface = packet.iface;
        key.proto = packet.proto;


		if(app.client.options.type == app.DEFS.TYPE.CONDENSE && app.client.options.type_sub == app.DEFS.TYPE.CONDENSE_SMART){
			return key;
		}

        if(app.client.options.type == app.DEFS.TYPE.CONDENSE && (key.proto == "TCP" || key.proto == "UDP")) {

            /*
             * Try and condense table by making client sports = 0
             *
             * uhg this is going to get dirty
             */

			if(app.client.options.type_sub == 0) {
				var tk = _.clone(key);
				var left_port_orig = tk.left_port;
				var right_port_orig = tk.right_port;

				tk.left_port = 0;
				var t_key = _.values(tk).join(',');

				if(app.client.tables.flows.data[t_key] != undefined) {
					return tk;
				}

				tk.left_port = left_port_orig;
				tk.right_port = 0;

				var t_key = _.values(tk).join(',');
				if(app.client.tables.flows.data[t_key] != undefined) {
					return tk;
				}

				tk.right_port = right_port_orig;
	
				if(packet.src == key.left) {
					key.left_port = 0;
					//return key;
				}
				else {
					key.right_port = 0;
					//return key;
				}

			
	        }

		}


        return key;
    },


    split_line: function(x) {
        /* Split a line into fields & organize it */
		var l = app.client.tables;

        if(x.indexOf("********") > 0) {
            return false;
        }

        var v = x.replace(/[;,]/g, '').split(/\s+/g);
		if(v.length < 5) {
			return null;
		}

        if(v[1] == "IP") {
			return app.client.tables.fn.split_line_pcap(v);
        }
		else {
			return app.client.tables.fn.split_line_iptraf(v);
		}

		return null;
	},



	split_line_pcap: function(v) {
		
		/*
		1361083134.289546 IP 10.200.1.18.54601 > 10.200.1.1.22: tcp 64
		1361083134.289610 IP 10.200.1.1.22 > 10.200.1.18.54601: tcp 32
		1361083134.291162 IP 10.200.1.18.54601 > 10.200.1.1.22: tcp 0
		1361083137.706761 IP 10.200.1.10.54013 > 10.200.1.1.1514: UDP, length 233
		1361083137.706803 IP 10.200.1.10.54013 > 10.200.1.1.1514: UDP, length 249
		1361083139.709033 IP 10.200.1.10.54013 > 10.200.1.1.1514: UDP, length 257
		1361115505.014528 IP 10.200.1.1 > 10.200.1.6: ICMP echo request, id 3104, seq 4, length 64
		1361115505.041035 IP 10.200.1.6 > 10.200.1.1: ICMP echo reply, id 3104, seq 4, length 64
		*/

		if(v[1] != "IP") {
			return {};
		}

		var obj = {};

		var size;

		var packet = _.clone(app.DEFS.PACKET);
		packet.iface = "manual";
		packet.ts_b = v[0];
		packet.proto = v[5].toUpperCase();
		packet.src = v[2];
		packet.dst = v[4].replace(/:/g, '');
		packet.bytes = 0;

		var len = null;
		switch(packet.proto) {
			case "TCP": {
				len = v[6];
			}
			case "UDP": {
				var t = packet.src.split('.');
				packet.src = t[0]+"."+t[1]+"."+t[2]+"."+t[3];
				packet.sport = parseInt(t[4],10);
				t = packet.dst.split('.');
				packet.dst = t[0]+"."+t[1]+"."+t[2]+"."+t[3]; 
				packet.dport = parseInt(t[4], 10);

				break;
			}
			default: {
				return {};
			}
		}

		len = v[v.length-1];

		if(len == null) {
			return {}
		}

		packet.bytes = parseInt(len,10);

 

		var obj = app.client.tables.fn.split_line_pkt(packet);

		return obj;
	},



	split_line_iptraf: function(v) {

        /* Sat Feb  9 01:31:58 2013; ICMP; eth0; 76 bytes; from 192.168.1.50 to 68.123.143.121; time excd */
        /* Sat Feb  9 01:28:28 2013; UDP; eth0; 417 bytes; from 199.193.251.108:53648 to 192.168.1.50:1194 */
        /* Sat Feb  9 01:29:14 2013; TCP; eth0; 84 bytes; from 192.168.1.50:22 to 192.168.1.101:36429; first*/

        /* Tue Feb 12 12:46:12 2013; TCP; eth0; 1281 bytes; from 199.193.251.107:80 to 192.168.1.50:54919; FIN sent; 123 packets, 181379 bytes, avg flow rate 1451.00 kbits/s 
         * 15 - packets sent
         * 17 - packet size
         */

        /* Wed Feb 13 01:15:41 2013; TCP; Connection 192.168.56.100:443 to 141.212.121.40:54622 timed out, 0 packets, 0 bytes, avg flow rate 0.00 kbits/s; opposite direction 240 packets, 10320 bytes, avg flow rate 0.00 kbits/s"}]}
         * Wed Feb 13 02:04:09 2013; TCP; Connection 192.168.56.100:403 to 216.152.252.211:63668 timed out, 0 packets, 0 bytes, avg flow rate 0.00 kbits/s; opposite direction 342 packets, 17328 bytes, avg flow rate 0.00 kbits/
         * 6 - Connection
         * 25 - packet bytes
         * 28 - flow
         */

        var size;
        if(v.length < 13) {
            size = parseInt(v[7], 10);
        }
        else if(v.length > 18 && v[20] == "flow") {
            size = parseInt(v[17], 10);
        }
        else if(v.length > 27 && v[29] == "flow") {
            size = parseInt(v[26], 10);
        }
        else {
            size = parseInt(v[7], 10);
        }


        var packet = _.clone(app.DEFS.PACKET);
        packet.proto = v[5].toUpperCase();
        packet.iface = v[6];
        packet.bytes = size;
        packet.src = v[10];
        packet.dst = v[12];
        packet.ts_b = new Date(Date.parse(v[0]+" "+v[1]+" "+v[2]+" "+v[3]+" "+v[4], "MM DD HH:mm:ss YYYY"));

        switch(packet.proto) {
            case "ICMP": {
                break;
            }
            case "TCP":
            case "UDP": {
                var t = packet.src.split(':');
                packet.src = t[0];
                packet.sport = t[1];
                t = packet.dst.split(':');
                packet.dst = t[0];
                packet.dport = t[1];
                break;
            }
            default: {
                break;
            }
        }


		var obj = app.client.tables.fn.split_line_pkt(packet);
		return obj;
	},


	split_line_pkt: function(packet) {

		var obj = {
		}

        packet.src_addr = app.misc.fn.ip2long(packet.src);
        packet.dst_addr = app.misc.fn.ip2long(packet.dst);

        obj.packet = packet;

        if(app.client.options.type == app.DEFS.TYPE.FULL) {
        }
        else if(app.client.options.type == app.DEFS.TYPE.CONDENSE) {
            /*
             * This needs to be in make_key
             */
        }
        else if(app.client.options.type == app.DEFS.TYPE.IPONLY) {
            packet.sport = '';
            packet.dport = '';
        }


        obj.key = app.client.tables.fn.make_key(packet);
        obj.key_str = _.values(obj.key).join(',');

        return obj;
    },



	_init_summary: function() {
		app.client.tables.summary.table = $(app.client.tables.summary.str.table).dataTable({
			"bSort": false,
			"bSortClasses": false,
			"bDeferRender": true,
			"aoColumns": [
				null,
				null,
				null,
				null,
				null,
				null,
				{ "bVisible"	: false },
				{ "bVisible"	: false },
			],
		});
	},

	_init_toptalk: function() {
		app.client.tables.toptalk.table = $(app.client.tables.toptalk.str.table).dataTable({
			"bSort": true,
			"bSortClasses": false,
			"bDeferRender": true,
			"sPaginationType:" : "full_numbers", 
			"aoColumns": [
				{ "bVisible"	: false },
				null,
				null,
				null,
			],		
		});
	},

	_init_flows: function() {
		app.client.tables.flows.table = $(app.client.tables.flows.str.table).dataTable({
			"sPaginationType": "full_numbers",
		/*	"sDom": 'W<"clear">lfrtip', */
			"bSortClasses": false,
			"bSort": true,
			"bDeferRender": true,
			"aoColumns": [
				{ "bVisible"	: false },
				null,
				null,
				null,
				null,
				null,
				null,
				null,
				null,
				null,
				null,
				null,
				null,
			],
		});

		$("body").delegate("tfoot input", "dblclick", function() {
			$(this).val('');
		});

		$("tfoot input").keyup(function(event) {
			app.client.tables.flows.table.fnFilter( this.value, $("tfoot input").index(this) , true); // true for regex
		});
	},

	_init: function() {

		$.fn.dataTableExt.sErrMode = 'throw';

		var t = app.client.tables;
		t.fn._init_summary();
		t.fn._init_toptalk();
		t.fn._init_flows();

/*
console.log("bleh", app.client.tables.flows.table.fnSettings());
console.log("bleh", app.client.tables.toptalk.table.fnSettings());
console.log("bleh", app.client.tables.summary.table.fnSettings());
*/

	}

}
