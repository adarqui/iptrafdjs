if(typeof exports === 'undefined') exports = [];
var module = module || {};


module.exports = function() {
	var self = this;

	self.load = function(a) {

		a.DEFS = {
			TYPE: {
				FULL: 0,
				CONDENSE: 1,
				IPONLY: 2,
				CONDENSE_SMART: 3,
			},
			MODE: {
				MANUAL: 0,
				IPTRAF: 1,
				PCAP: 2,
			},
			RESOLVE: {
				NORMAL		: 0,
				DNS			: 1,
				GEOIP		: 2,
				GEOIP_DNS	: 3,
			},
			CHANNELS: {
				IPTRAF	: "iptraf",
				MODE	: "mode",
				BW		: "bw",
				PCAP	: "pcap",
				OPTIONS	: "options",
			},
			KEY: {
				iface: {},
				proto: {},
				left: {},
				left_port: {},
				right: {},
				right_port: {},
			},
			PACKET: {
				proto: {},
				iface: {},
				bytes: 0,
				src: {},
				sport: '',
				dst: {},
				dport: '',
	
				tx_src: 0,
				tx_dst: 0,
				total_bytes: 0,
	
				ts_tot: 0,
				ts_b: 0,
				ts_e: 0,
			},
			SUMMARY: {
               	iface   : {},
                tot     : 0,
                tcp     : 0,
                udp     : 0,
                icmp    : 0,

                ts_tot  : 0,
                ts_b    : 0,
                ts_e    : 0,
			},
			RESOLVE_STRUCT: { // for app.client.resolve hash
				name	: {},
				country	: {},
				org		: {},
				asnum	: {},
			},
		}


	a.io = {},

	a.fn = {
		parse_iptraf: {},
		parse_pkt	: {},
		parse_obj	: {},
		resolve		: {},
	}

	a.server = {
		fn: {
			init: {
				_init		: {},
				express		: {},
				https		: {},
				interfaces	: {},
				iptraf		: {},
				pcap		: {},
				pcap_handler: {},
			},
		},
		client: {
			fn: {
				handle: {
					connection: {},
					bandwidth: {},
					resolve: {},
					mode: {},
					listeners: {
						bandwidth: {},
					},
				},
				init: {
					bandwidth: {},
					iptraf: {},
					pcap: {},	
				},
			},
			config: {
				mode	: a.DEFS.MODE.MANUAL,
				type	: a.DEFS.TYPE.FULL,
				resolve	: a.DEFS.RESOLVE.NORMAL,	
				bw		: {},
				ifs		: {},
				timer	: null,
			},
		},
	},

	a.client = {

        flows: {},
        summary: {},
        toptalk: {},

		io: {
			fn: {
				_init: {},
				init_hooks: {},

				handle: {
					line: {},
				},

			},
			options: {
				reconnect	: 0, // if this is > 1, means we already connected previously
			},
			njs		: false,
			socket	: {
				emit: function() { }
			},
		},


		layout: {
			accordion: {
				str: {
					output: "#output",
				},
				fn: {
					_init			: {},
					init_portlets	: {},
				},
			},
		},


		control: {
			/* Control menu: user input, type, mode, reset, etc */
			export: {
				str: {
					export	: "#export",
					dialog	: "#export_dialog",
					textarea: "#export_textarea",
				},
				fn: {
					_init	: {},
					handle	: {
						click	: {},
					},
				},
			},
			manual: {
				str: {
					go		: "#go",
					input	: "#input",
					reset	: "#reset",
				},
				fn: {
					_init		: {},
					handle: {
						go		: {},
						input	: {},
						reset	: {},
					},
				},
			},
			type: {
				str: {
					filter	: "#filter",
					filters	: [ 'condense', 'iponly', 'full', 'condense_smart' ],
				},
				fn: {
					_init	: {},
					handle: {
						change: {},
					},
				},	
			},
			mode: {
				str: {
					mode	: "#mode",
					modes	: [ 'manual' , 'iptraf' , 'pcap' ],
				},
				fn: {
					_init	: {},
					handle: {
						change: {},
					},
				},
			},	
			resolve: {
				str: {
					resolve	: "#resolve",
					resolves: [ 'normal', 'dns', 'geoip', 'geoip_dns' ],
				},
				fn: {
					_init	: {},
					handle	: {
						change: {},
						resolve: {},
					},
					resolve: {},
				},
				data			: {},
				data_service	: {},
			},
		},

		tables: {
			flows: {
				str: {
					table	: "#table", //table
					head	: "#table_h", //thead
					body	: "#table_b", //tbody
 				},
				fn: {
					_init	: {},
				},
				table		: {},
				data		: {},
			},
			toptalk: {
				str: {
					table	: "#toptalk",
					head	: "#toptalk_h",
					body	: "#toptalk_b",
				},
				fn: {
					_init	: {},
				},
				table		: {},
				data		: {},
			},
			summary: {
				str: {
					table	: "#summary",
					head	: "#summary_h",
					body	: "#summary_b",
				},
				fn: {
					_init	: {},
					update	: {},
				},
				table		: {},
				data		: {},
			},
			fn: {
				_init		: {},
				_init_summary : {},
				_init_toptalk : {},
				_init_full	  : {},
				make_table_key		: {},
				reverse_table_key	: {},
				make_toptalk_key	: {},
				make_key			: {},
				split_line			: {},
				split_line_pkt		: {},
				split_line_pcap		: {},
				split_line_iptra	: {},
			},
			str: {
				graphs	: ".graphs",
			},
		},

		charts: {
			toptalk: {
				str: {
					reset		: "#chart_toptalk_reset",
					chart		: "#chart_toptalk",
				},
				fn: {
					_init		: {},
					handle: {
						update_doit		: {},
						update_override	: {},
						update			: {},
						reset			: {},
					},
				},
				chart: {},
				inc: 0,
			},

			summary: {
				str: {
					reset		: "#chart_summary_reset",
					chart		: "#chart_summary",
				},
				fn: {
					_init		: {},
					handle: {
						update	: {},
						reset	: {},
					},
				},
				chart	: {},
				inc		: 0,
			},
				
			bandwidth: {
				str: {
					interval	: "#chart_bandwidth_interval",
					save		: "#chart_bandwidth_save",
					reset		: "#chart_bandwidth_reset",
					chart		: "#chart_bandwidth",
				},
				fn: {
						_init		: {},
					handle: {
						io			: {},
						save		: {},
						reset		: {},
						interval	: {},
					},
				},
				chart: {},
				interfaces: null,
				inc: 0,
			},
			fn: { /* Generic chart functions */
				_init: {},
				reset: {},
				build: {},
				click: {},
			},
			str: {
				graphs	: "#tabs_graphs",
				graphsc	: "#graphsc",
			},
		},

		str: {
			tabs        : {
				graphs  : "#tabs_graphs",
			},
		},

		debug: {
			log: console.log
		},


		options: {
			type	: a.DEFS.TYPE.CONDENSE,
			type_sub: a.DEFS.TYPE.CONDENSE_SMART,
			mode	: a.DEFS.MODE.MANUAL,
			resolve	: a.DEFS.RESOLVE.NORMAL,
			graphs	: 0,
		},

	}


		a.misc = {
			fn: {
				trav: {}
			},
		}

}



return self;
}
