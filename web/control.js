var app = app || {};
app.modules = app.modules || {};

var control = function() {
	var self = this;
	self.control = app.client.control;
	self.control.fn._init();
}


app.modules['control'] = control;

app.client.control.export.fn = {

	handle: {
		click: function() {
			var e = app.client.control.export;

			$(e.str.dialog).dialog({
				height: 700,
				width: 900,
				modal: true,
			});
			$(e.str.textarea).val('');
			
			var dat = "";

/*
			console.log(app.client.tables.toptalk.data);
			console.log(app.client.tables.summary.data);
			console.log(app.client.tables.flows.data);	
*/

			/* Sort the tables first */
			app.client.tables.toptalk.table.fnSort([[3, 'desc']]);
			app.client.tables.flows.table.fnSort([[7, 'desc']]);

			dat = "Results from IPTRAF Analyzer\n";

			var tt = app.client.tables.toptalk.table;
			dat = dat + "\nTop Talkers:\n";
			var nodes = tt._('tr', { "filter":"applied"});
			for(var v in nodes) {
				var node = nodes[v];
				dat = dat + "interface=" + node[1] + " , ip=" + node[2] + " , total_bytes=" + node[3] + "\n";
			}

	
			var s = app.client.tables.summary.data;
			dat = dat + "\nGeneral interface statistics:\n";
			for(var v in s) {
				var s_iface = s[v];
				dat = dat + "iface=" + v + " , total_bytes=" + s_iface.tot + " , icmp=" + s_iface.icmp + " , tcp=" + s_iface.tcp + " , udp=" + s_iface.udp + " , time=" + s_iface.ts_tot.toFixed(2) + "\n";
			}


			var f = app.client.tables.flows.table;
			dat = dat + "\nFlows:\n";
			var nodes = f._('tr', { 'filter':'applied'});
			console.log(nodes);
			for(var v in nodes) {
				var node = nodes[v];
				dat = dat + "interface=" + node[1] + " , total_bytes=" + node[7] + " , proto=" + node[2] + " , src=" + node[3] + " , dst=" + node[5] + " , sport=" + node[4] + " , dport=" + node[6] + " , time=" + node[10] + "\n";

			}
			
			$(e.str.textarea).val(dat);

		},
	},

	_init: function() {
		var e = app.client.control.export;
		$('body').delegate(e.str.export, 'click', e.fn.handle.click);
	},
}

app.client.control.type.fn = {

	handle: {
		change: function() {

	        app.client.options.type = 0;

        	var v = $(app.client.control.type.str.filter).val();
        	switch(v) {
            	case "iponly": {
                	app.client.options.type = app.DEFS.TYPE.IPONLY;
					app.client.options.type_sub = 0;
                	break;
            	}
            	case "condense": {
                	app.client.options.type = app.DEFS.TYPE.CONDENSE;
					app.client.options.type_sub = 0;
                	break;
            	}
            	case "full": {
                	app.client.options.type = app.DEFS.TYPE.FULL;
					app.client.options.type_sub = 0;
                	break;
            	}
				case "condense_smart": {
					app.client.options.type = app.DEFS.TYPE.CONDENSE;
					app.client.options.type_sub = app.DEFS.TYPE.CONDENSE_SMART;
					break;
				}
            	default: {
                	break;
            	}
        	}

			localStorage[app.client.control.type.str.filter] = v;
		},
		
	},

	_init: function() {
		var t = app.client.control.type;
		$('body').delegate(t.str.filter, 'change', t.fn.handle.change);
		var val = localStorage[t.str.filter];
		$(t.str.filter).val(val);
		t.fn.handle.change();
	},

}



app.client.control.resolve.fn = {
	handle: {
		change: function() {
			app.client.options.resolve = app.DEFS.RESOLVE.NORMAL;
			var v = $(app.client.control.resolve.str.resolve).val();
			switch(v) {
				case "normal": {
					app.client.options.resolve = app.DEFS.RESOLVE.NORMAL;
					break;
				}
				case "dns": {
					app.client.options.resolve = app.DEFS.RESOLVE.DNS;
					break;
				}
				case "geoip": {
					app.client.options.resolve = app.DEFS.RESOLVE.GEOIP;
					break;
				}
				case "geoip_dns": {
					app.client.options.resolve = app.DEFS.RESOLVE.GEOIP_DNS;
					break;
				}
				default: {
					break;
				}
			}

			app.io.socket.emit(app.DEFS.CHANNELS.RESOLVE, { resolve: app.client.options.resolve });
			localStorage[app.client.control.resolve.str.resolve] = v;
		},

		resolve: function(data) {
		/*
		 * OMG.
		 */

			var which;
			var reverse = null;
			if(data.host != undefined) {
				which = data.host;

				reverse = data.reverse.length > 1 ? data.reverse[0] : data.reverse[0];

				app.client.control.resolve.data[data.host] = {
					reverse: reverse,
				}

			}
			else if(data.port != undefined) {
				which = data.port;

			app.client.control.resolve.data_service[data.port] = {
					service : data.service.name,
					desc	: data.service.description,
				}
			}

			var tr = app.client.tables.flows.table.fnFindCellRowIndexes(which);
			if(tr.length != 0) {
				for(var v in tr) {
					var rows = app.client.tables.flows.table.fnGetData(tr[v]);
					if(data.host != undefined && reverse != null) {
						if(rows[3] == data.host) {
							rows[3] = reverse;
						}
						if(rows[5] == data.host) {
							rows[5] = reverse;
						}
					}
					if(data.port != undefined && data.service != undefined) {
						if(rows[4] == data.port) {
							rows[4] = data.service.name;
						}
						if(rows[6] == data.port) {
							rows[6] = data.service.name;
						}
					}
					app.client.tables.flows.table.fnUpdate(rows, tr[v]);
				}
			}
			
		},
	},

	resolve: function(flow) {

		var r = app.client.control.resolve;

		if(app.client.options.resolve == app.DEFS.RESOLVE.NORMAL) {
			return false;
		}

        var exist = r.data[flow.src];
            if(exist == undefined) {
                app.io.socket.emit(app.DEFS.CHANNELS.RESOLVE, { host: flow.src });
				r.data[flow.src] = {};
            }
        var exist = r.data[flow.dst];
            if(exist == undefined) {
                app.io.socket.emit(app.DEFS.CHANNELS.RESOLVE, { host: flow.dst });
				r.data[flow.dst] = {};
            }

		if(flow.proto != "TCP" && flow.proto != "UDP") {
			return false;
		}
    

        var exist_service = r.data_service[flow.sport];
			if(exist_service == undefined) {
				app.io.socket.emit(app.DEFS.CHANNELS.RESOLVE, { port: flow.sport });
				r.data_service[flow.sport] = {};
			}
		var exist_service = r.data_service[flow.dport];
			if(exist_service == undefined) {
				app.io.socket.emit(app.DEFS.CHANNELS.RESOLVE, { port: flow.dport });
				r.data_service[flow.dport] = {};
			}

		return true;
    },


	_init: function() {
		var r = app.client.control.resolve;
		$('body').delegate(r.str.mode, 'change', r.fn.handle.change);

		var val = localStorage[r.str.resolve];
		$(r.str.resolve).val(val);
		r.fn.handle.change();

		app.io.socket.on(app.DEFS.CHANNELS.RESOLVE, r.fn.handle.resolve);
    },

}

app.client.control.mode.fn = {

	handle: {
		change: function() {

            app.client.options.mode = app.DEFS.MODE.MANUAL;

            var v = $(app.client.control.mode.str.mode).val();
            switch(v) {
                case "manual": {
					$(app.client.control.manual.str.input).attr('disabled', false);
                    app.client.options.mode = app.DEFS.MODE.MANUAL;
                    break;
                }
                case "iptraf": {
					alert("iptraf parser is deprecated, use pcap");
					$(app.client.control.manual.str.input).attr('disabled', true);
                    app.client.options.mode = app.DEFS.MODE.PCAP;
					v = "pcap";
                    break;
                }
                case "pcap": {
					$(app.client.control.manual.str.input).attr('disabled', true);
                    app.client.options.mode = app.DEFS.MODE.PCAP;
                    break;
                }
                default: {
                    break;
                }
            }

			app.io.socket.emit(app.DEFS.CHANNELS.MODE, { mode: app.client.options.mode });
			localStorage[app.client.control.mode.str.mode] = v;
        },
	},

	_init: function() {
		var m = app.client.control.mode;
		$('body').delegate(m.str.mode, 'change', m.fn.handle.change);
	
		var val = localStorage[m.str.mode];
		$(m.str.mode).val(val);
		m.fn.handle.change();
	},

}





app.client.control.manual.fn = {

	handle: {
		go: function() {


	        var log = $(app.client.control.manual.str.input).val();
        	var lines = log.split('\n');

        	app.client.control.type.fn.handle.change(); // make sure we have the latest filter option
//console.log("d", app,app.fn);
	        app.fn.parse({ requester: 1, x: lines });

   //     app.fn.powertips();
			app.client.tables.flows.table.fnDraw();
			app.client.tables.summary.table.fnDraw();
			app.client.tables.toptalk.table.fnDraw();
			
			app.client.tables.toptalk.table.fnSort([[3, 'desc']]);

			/* OVERRIDE FOR CHARTS */
			for(var v in app.client.tables.toptalk.data) {
				var flows = app.client.tables.toptalk.data[v];
				for(y in flows) {
					var flow = flows[y];
					/*console.log(y, flow); */
					app.client.charts.toptalk.fn.handle.update_override({ src: y, total_bytes: flow.total_bytes });
				}
			}

			

		},
		input: function() {

        	$(app.client.control.manual.str.input).val('');
    	},

		reset: function() {
        	app.client.control.manual.fn.handle.input();

	        app.client.tables.flows.data = {};
        	app.client.tables.summary.data = {};
        	app.client.tables.toptalk.data = {};

        	app.client.tables.flows.table.fnClearTable();
			app.client.tables.toptalk.table.fnClearTable();
			app.client.tables.summary.table.fnClearTable();

			app.client.charts.bandwidth.fn.handle.reset();
			app.client.charts.toptalk.fn.handle.reset();
			app.client.charts.summary.fn.handle.reset();
// clear charts
    	},

	},

	_init: function() {
		var m = app.client.control.manual;
		$('body').delegate(m.str.go, "click", m.fn.handle.go);
		$('body').delegate(m.str.input, "dblclick", m.fn.handle.input);
		$('body').delegate(m.str.reset, "click", m.fn.handle.reset);	
	},

}


app.client.control.fn = {

	_init: function() {
		// ...
		var c = app.client.control;
		c.manual.fn._init();
		c.type.fn._init();
		c.mode.fn._init();
		c.resolve.fn._init();
		c.export.fn._init();

		app.io.socket.emit(app.DEFS.CHANNELS.OPTIONS, app.options);
	}
}
