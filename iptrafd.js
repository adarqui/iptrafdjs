/*
 * IPTRAFD - IPTRAF Daemon - For the iptraf analyzer PoC
 * adarqui 2/20/2013 @ adarq.org
 */


var app = app || {};

/*
 * These vars are shared between server & agents
 */

app.deps = {
	express	: require('express'),
	ejs		: require('ejs'),
	crypto	: require('crypto'),
	fs		: require('fs'),
	http	: require('https'),
	sys		: require('sys'),
	io		: require('socket.io'),
	_		: require('underscore'),
	dns		: require('dns'),
	tailfd	: require('tailfd'),
	os		: require('os'),
	pcap	: require('pcap'),
	inc		: require('./web/include.js'),
	service	: require('service-names'),
}

app.tools = {
	r		: function(x) { return require(__dirname + "/" + x); },
	rn		: function(x, args) { var m = r(x); return new m(args); },
}

app.conf = {
	argv		: {},
	sock		: {},
	dir			: __dirname+"/",
	port		: 65503,
	mode		: null, // server or agent
	web			: __dirname+"/web/",

	ssl: {
		key		: app.deps.fs.readFileSync(__dirname + '/keys/key.pem'),
		cert	: app.deps.fs.readFileSync(__dirname + '/keys/cert.pem'),
	},

	/*
	 * bw: when this is set to true, clients that connect will get a bandwidth feed of ever if
	 */
	bw			: {
		enabled	: true,
		interval: 5000,
		timer	: {},
		profile	: null,
	},


	/*
	 * These are all of the interfaces we will monitor with pcap
	 */
	pcap: {
		enabled: true,
		ifs: {
/*
			tun0: {
				name	: "tun0",
				filter	: "not net 10.0.0.0/8",
				session	: {},
			},
*/
			eth0: {
				name	: "eth0_pcap",
				filter	: "not port 65503 and not port 1194 and not host 192.168.1.101 and not host 64.135.14.158",
				session	: {},
			},
			// ...
		},
	},
 
	/*
	 * These are all of the logs that iptrafd.js will read & broadcast
	 */
	logs: {
		wan: {
			log:  "/var/log/iptraf/eth0.log",
			filters: [
						[ "192.168.1.50:65503" ], // this nodejs web server
						[ "192.168.1.50:1194" ], // authorized vpn traffic
			],
			watcher: {},
		},
		pot: {
			log: "/var/log/iptraf/tun0.log",
			filters: [
						[ "10.200.1" ], // get rid of vpn traffic
			],
			watcher: {},
		},
	}
}


app.deps.inc = app.deps.inc();
app.deps.inc.load(app);


app.server.fn = {

	notify: function(x) {
		/* x.channel
		 * x.data
		 * x.cb : if return true, notify, if false, dont.. arg is sock
		 */

		var sockets = app.conf.sock.app.sockets.sockets;

		for(var v in sockets) {
			var socket = sockets[v];

			if(x.cb != undefined) {
				var truth = x.cb(socket);
				if(truth == false) continue;
			}

			socket.emit(x.channel, x.data);
		}
	},

}



app.server.client.fn.handle = {

	connection: function(socket) {

		var c = app.server.client;

		//console.log("connection");

		var self = this;

		/*
		 * config {
		 *  mode = ..
		 *  resolve = if set, geoip, dns, etc
		 *  bw: contains the bandwidth monitoring variables
		 */

		self.config = app.deps._.clone(c.config);
		self.socket = socket;
		socket.config = self.config;
    
		self.init = {

			loguser: function() {
				var address = self.socket.handshake.address;
				var d = new Date();
				app.deps.fs.appendFile(app.conf.dir+"users.txt", 
					address.address + " : " + d.toString() + "\n", function(err) {
				});
			},

			bandwidth: function() {
				if(app.conf.bw.enabled == true) {

					if(self.config.bw.timer != null) {
						clearInterval(self.config.bw.timer);
					}

					self.config.bw.timer = setInterval(function() {
						//console.log("app.conf.bw", self.config.bw);
						self.handle.listeners.bandwidth(socket);
					}
					, self.config.bw.interval);
           		}

			},

		}


		self.handle = {

			options: function(data) {
				//console.log("options:", data);
			},

			bandwidth: function(data) {
				//console.log("handle_bw", data);

				if(data.interval != undefined) {
					if(data.interval <= 0) {
						data.interval = 5;
					}
	
					data.interval *= 1000;

					self.config.bw.interval = data.interval;
					self.init.bandwidth();
					}
				},

			mode: function(data) {

				//console.log("handle_mode", data);

				this.config.mode = data.mode;
				//console.log("this.config", this.config);
			},

			resolve_dns: function(data) {
				//console.log("resolve dns", data);


				app.deps.dns.reverse(data, function(err, domains) {
					if(err) {
						return false;
					}
					//console.log("dns.resolve", domains);
					self.socket.emit(app.DEFS.CHANNELS.RESOLVE, { host: data, reverse: domains });
				});
			},

			resolve_geoip: function(data) {
				//console.log("resolve geoip");
			},

			resolve_service: function(data) {
				//console.log("resolve service", data);

				var service = app.deps.service.tcp[data] || app.deps.service.udp[data];
				if(service != undefined) {
					if(service.name == undefined) {
						service.name = data;
					}
					if(service.name == "Reserved") {
						service.name = data;
					}
					self.socket.emit(app.DEFS.CHANNELS.RESOLVE, { port: data, service: service });
					return true;
				}
				

			},

			resolve: function(data) {
				var resolve = data.resolve;

				if(data.host != undefined) {
					self.resolve_handler(data.host);
					return true;
				}
				if(data.port != undefined) {
					self.handle.resolve_service(data.port);
					return true;
				}

				switch(resolve) {
					case app.DEFS.RESOLVE.NORMAL: {
						self.resolve_handler = function() { };
						break;
					}
					case app.DEFS.RESOLVE.DNS: {
						self.resolve_handler = self.handle.resolve_dns;
						break;
					}
					case app.DEFS.RESOLVE.GEOIP: {
						self.resolve_handler = self.handle.resolve_geoip;
						break;
					}
					case app.DEFS.RESOLVE.GEOIP_DNS: {
						self.resolve_handler = function(data) {
							self.handle.resolve_dns(data);
							self.handle.resolve_geoip(data);
						}
						break;
					}
					default: {
						return false;
					}
				}

				//console.log("resolve:", resolve);


			},

			listeners: {

				bandwidth: function(socket) {
					//console.log("handle_bandwidth", socket.config.bw.interfaces);

					socket.emit(app.DEFS.CHANNELS.BW, { ifs: socket.config.bw.interfaces });

					for(var v in socket.config.bw.interfaces) {

						var iface = socket.config.bw.interfaces[v];
						//console.log("v", v, "iface", iface);
						if(v.indexOf(':') > 0) { continue; }

						app.deps.fs.readFile("/sys/class/net/"+v+"/statistics/rx_bytes", (function(err, line_rx) {

							var z = iface;
							return function(err, line_rx) {

								if(err) {
									return false;
								}
								line_rx = parseInt(line_rx);
								z.rxA = z.rxB;
								z.rxB = line_rx;
							}

						}(iface)));

						app.deps.fs.readFile("/sys/class/net/"+v+"/statistics/tx_bytes", (function(err, line_tx) {
							var z = iface;
								return function(err, line_tx) {
									if(err) {
										return false;
									}
									line_tx = parseInt(line_tx);
									z.txA = z.txB;
									z.txB = line_tx;
								}
						}(iface)));
					}
				}
			}
			}

			socket.on(app.DEFS.CHANNELS.MODE, self.handle.mode);
			socket.on(app.DEFS.CHANNELS.BW, self.handle.bandwidth);
			socket.on(app.DEFS.CHANNELS.RESOLVE, self.handle.resolve);

			socket.config.bw = app.deps._.clone(app.conf.bw);
			socket.config.bw.interfaces = app.deps._.clone(app.conf.interfaces);

			self.init.loguser();
			self.init.bandwidth();

			/*
			 * Important socket events
			 */
			socket.on("disconnect", function(data) {
				clearInterval(self.config.bw.timer);
			});

		}
	}


app.server.fn.init = {

    https: function() {
        //console.log("init_https");

        app.server_socket = app.deps.http.createServer(app.conf.ssl, app.conf.express).listen(app.conf.port);
        app.conf.sock.app = app.deps.io.listen(app.server_socket);

        app.conf.sock.app.sockets.on('connection', function(socket) {
			//console.log("app", app);
			app.server.client.fn.handle.connection(socket);
		});
	},


	express: function() {
		//console.log("init_express");

		app.conf.express = app.deps.express();

		app.conf.express.configure(function() {
			app.conf.express.engine('html', app.deps.ejs.renderFile);
			app.conf.express.set('view engine', 'html');
			app.conf.express.use(app.deps.express.static(app.conf.web));
			app.conf.express.get('/', function(req, res) { res.render('index'); });
		});
	},


	interfaces: function() {

        //console.log("init_interface_profile");

        app.conf.interfaces = app.deps.os.networkInterfaces();

        var i = 0;
        for(var v in app.conf.interfaces) {
            //console.log(app.conf.interfaces);
            if(v.indexOf(':') > 0) {
        		delete app.conf.interfaces[v] ;
                continue;
            }
            app.conf.interfaces[v] = {
                name    : v,
                rxA     : 0,
                rxB     : 0,
                txA     : 0,
                txB     : 0,
                index   : i,
            }
            i = i + 1;
        }

    },


         iptraf: function() {
                //console.log("init_log_listeners");

                for(var v in app.conf.logs) {
                    var log = app.conf.logs[v];

                    //console.log(log);

                    log.watcher = app.deps.tailfd(log.log, (function(line, tailinfo) {
                        var entry = app.conf.logs[v];
                        return function(line, tailinfo) {
                            for(var w in entry.filters) {
                                if(line.indexOf(entry.filters[w]) > 0) {
                                    return false;
                                }
                            }

                            app.server.fn.notify({
                                channel: app.DEFS.CHANNELS.IPTRAF,
                                data: { line: line },
								cb: function(socket) {
									if(socket.config.mode == app.DEFS.MODE.IPTRAF) {
										return true;
									}
									else {
										return false;
									}
								},
                            });
                        }
                    }(v)));
                }
            },
    
	pcap: function() {
		//console.log("pcap");

		var p = app.conf.pcap;

		if(p.enabled != true) {
			return false;
		}

		for(var v in p.ifs) {
			var pe = p.ifs[v];
			pe.session = app.deps.pcap.createSession(v, p.ifs[v].filter);				
			pe.session.on('packet', (function(packet) {
				var new_v = v;
				return function(packet) {
					packet.interface = p.ifs[new_v].name;
					app.server.fn.init.pcap_handler(packet);
				}
			}(v)));
			pe.session.on('error', function() {
				console.log("error");
			});
			
		}
	},

	pcap_handler: function(packet) {

				var decoded = app.deps.pcap.decode.packet(packet);
				var pcap_header = decoded.pcap_header;
				if(decoded.link.ip == undefined) {
					return false;
				}

				var packet_hdr = app.deps._.clone(app.DEFS.PACKET);

				packet_hdr.proto	= decoded.link.ip.protocol_name;
				packet_hdr.iface	= packet.interface;
				packet_hdr.bytes	= decoded.link.ip.total_length;
				packet_hdr.src		= decoded.link.ip.saddr;
				packet_hdr.dst		= decoded.link.ip.daddr;
				packet_hdr.ts_b		= pcap_header.time_ms;
				
				var ptr = null;
				if(packet_hdr.proto == "TCP") {
					ptr = decoded.link.ip.tcp;
				}
				else if(packet_hdr.proto == "UDP") {
					ptr = decoded.link.ip.udp;
				}
				else if(packet_hdr.proto == "ICMP") {
				}
				else {
					return false;
				}

				if(ptr != null) {
					packet_hdr.sport = ptr.sport;
					packet_hdr.dport = ptr.dport;
				}

                            app.server.fn.notify({
                                channel: app.DEFS.CHANNELS.PCAP,
                                data: { pkt: packet_hdr },
                                cb: function(socket) {
                                    if(socket.config.mode == app.DEFS.MODE.PCAP) {
                                        return true;
                                    }
                                    else {
                                        return false;
                                    }
                                },
                            });

	},

	_init: function() {
		//console.log("init", app);

		process.on('uncaughtException', function(exception) {
			console.log("uncaught exception: ", exception);
		});

		app.server.fn.init.express();
		app.server.fn.init.interfaces();
		app.server.fn.init.https();
		app.server.fn.init.iptraf();
		app.server.fn.init.pcap();
	},

}

app.server.fn.init._init();
