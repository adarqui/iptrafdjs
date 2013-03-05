/* adarqui 2/20/2013 @ adarq.org */


/* include.js for a 'layout' of the code, helpful.. */
var app = app || {};

$(document).ready(function() {
	//console.log("ready");

	if(module != undefined) {
		module.exports().load(app);	
	}

	var list = 
		[ "io.js", "layout.js", "control.js",  "tables.js", "bandwidth.js", "toptalk.js", "summary.js", "charts.js", "misc.js" ];

	for(var v in list) {
		$('head').append('<script src="'+list[v]+'"></script>');
	}


app.fn = {

	parse: function(y) {
		var x = y.x;

		app.fn.parse_iptraf(y);
	},

	parse_pcap: function(y) {
		var x = y.x;

		for(var v in x) {
			var obj = app.client.tables.fn.split_line_pkt(x[v]);
			app.fn.parse_obj({ requester: y.requester, obj: obj });
		}
	},

	
	parse_iptraf: function(y) {
		/*
		 * Parse log files: x = array of lines
		 * y = container obj
		 * x = line etc
		 */
		var x = y.x;

		var flows = app.client.tables.flows;
		var summary = app.client.tables.summary;
		var toptalk = app.client.tables.toptalk;


		var flow;

		for(var v in x) {
			var line = x[v];
			var obj = app.client.tables.fn.split_line(line);
			app.fn.parse_obj({ requester: y.requester, obj: obj });
		}
	},



	parse_obj: function(y) {

		var obj = y.obj;
		var requester = y.requester;

		var flows = app.client.tables.flows;
		var summary = app.client.tables.summary;
		var toptalk = app.client.tables.toptalk;


			if(obj == false) {
				return false;
			}

			if(obj == undefined || obj.packet == undefined) {
				return false;
			}

			if(obj.packet.proto != "ICMP" && obj.packet.proto != "TCP" && obj.packet.proto != "UDP") {
				return false;
			}

			flow = flows.data[obj.key_str];
			if(flow == undefined) {
				/*
				 * New flow
				 */
				flows.data[obj.key_str] = _.clone(obj.packet);
				flow = flows.data[obj.key_str];
				flow.total_bytes = obj.packet.bytes;

				flow.first_packet = obj.packet.src;

				if(flow.first_packet == obj.packet.src) {
					flow.tx_src = flow.tx_src + obj.packet.bytes;
				}
				else {
					flow.tx_dst = flow.tx_dst + obj.packet.bytes;
				}
			}
			else {
				/*
				 * Existing, update
				 */
				flow.total_bytes = flow.total_bytes + obj.packet.bytes;

				if(flow.first_packet == obj.packet.src) {
					flow.tx_src = flow.tx_src + obj.packet.bytes;
				}
				else {
					flow.tx_dst = flow.tx_dst + obj.packet.bytes;
				}

				flow.ts_e = obj.packet.ts_b;
				flow.ts_tot = flow.ts_e - flow.ts_b;

			}




			/* TRANSLATIONS */
			var z_src = null, z_dst = null, z_sport = null, z_dport = null;
if(app.client.options.resolve > 0) {
			var z = app.client.control.resolve.data[flow.src];
			if(z != undefined) {
				if(z.reverse != undefined) {
					z_src = z.reverse;
				}
			}
			var z = app.client.control.resolve.data[flow.dst];
			if(z != undefined) {
				if(z.reverse != undefined) {
					z_dst = z.reverse;
				}
			}

			var z = app.client.control.resolve.data_service[flow.sport];
			if(z != undefined && z.service != undefined) {
				z_sport = z.service;
			}
			var z = app.client.control.resolve.data_service[flow.dport];
			if(z != undefined && z.service != undefined) {
				z_dport = z.service;
			}
}




			/* Always update 'bytes' with latest count: for summary etc */
			flow.bytes = obj.packet.bytes;


			// top talkers
			if(toptalk.data[flow.iface] == undefined) {
				toptalk.data[flow.iface] = {};
			}
			if(toptalk.data[flow.iface][flow.src] == undefined) {
				toptalk.data[flow.iface][flow.src] = {
					total_bytes: 0
				};
			}

			toptalk.data[flow.iface][flow.src].total_bytes += obj.packet.bytes;

			/*
			 * UPDATE TOP TALKERS TABLE
			 */

/*
0                        <th>Key</th>
1                        <th>Interface</th>
2                        <th>IP</th>
3                        <th>Total Bytes</th>
*/

			var toptalk_key = app.client.tables.fn.make_toptalk_key(flow);
			var tr = toptalk.table.fnFindCellRowIndexes(toptalk_key,0);
			if(tr.length == 0) {
				toptalk.table.fnAddData(
					[ toptalk_key, flow.iface, /*flow.src*/ z_src != null ? z_src : flow.src, toptalk.data[flow.iface][flow.src].total_bytes ]
				, requester > 0 ? false : true);
			} else {
				var row = toptalk.table.fnGetData(tr[0]);
				row[3] = toptalk.data[flow.iface][flow.src].total_bytes;
				if(z_src!=null) { 
					row[2] = z_src;
				}
				toptalk.table.fnUpdate(row, tr[0], undefined, requester > 0 ? false : true);
			}


			app.client.charts.toptalk.fn.handle.update({
				iface: flow.iface,
				src: flow.src,
				total_bytes: toptalk.data[flow.iface][flow.src].total_bytes
			});


if(requester == 2) {
app.client.tables.toptalk.table.fnStandingRedraw();
}


			/*
			 * UPDATE TABLE
			 */

/*
0                        <th>Interface</th>
1                        <th>Protocol</th>
2                        <th>Client IP</th>
3                        <th>Client Port</th>
4                        <th>Server IP</th>
5                        <th>Server Port</th>
6                        <th>Total Bytes</th>
7                        <th>TX Cli to Serv</th>
8                        <th>TX Serv to Cli</th>
9						 <th>Total Time</th>
10						 <th>Start Time</th>
11						 <th>End Time</th>
*/


			var tbl_key = app.client.tables.fn.make_table_key(obj.key_str);

			var tr = flows.table.fnFindCellRowIndexes(tbl_key,0);

/*
			if(flow.proto == "ICMP") {
				flow.sport = 0;
				flow.dport = 0;
			}
*/

			if(tr.length == 0) {
				flows.table.fnAddData(
					[ tbl_key, flow.iface, flow.proto, /*flow.src*/ z_src != null ? z_src : flow.src, /*flow.sport*/ z_sport != null ? z_sport : flow.sport, /*flow.dst*/ z_dst != null ? z_dst : flow.dst, /*flow.dport*/ z_dport != null ? z_dport : flow.dport, 
					flow.total_bytes, flow.tx_src, flow.tx_dst, flow.ts_tot.toFixed(2), flow.ts_b, flow.ts_e
					]
				, requester > 0 ? false : true);
			} else {

				var row = flows.table.fnGetData(tr[0]);
				row[7] = row[7] + obj.packet.bytes;
				row[8] = flow.tx_src;
				row[9] = flow.tx_dst;
				row[10] = flow.ts_tot.toFixed(2);
				row[11] = flow.ts_b;
				row[12] = flow.ts_e;
				flows.table.fnUpdate(row, tr[0], undefined, requester > 0 ? false : true);
			}

if(requester == 2) {
app.client.tables.flows.table.fnStandingRedraw();
}

		/* DNS/GEOIP HOOKS */
		app.client.control.resolve.fn.resolve(flow);

		app.client.tables.summary.fn.update({ requester: y.requester, flow: flow });
	},

	init: function() {
	},


}


 for(var v in app.modules) {
        app.modules[v] = new app.modules[v]();
    }

/* Here we go. */

 app.fn.init();
});
