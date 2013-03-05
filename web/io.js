var app = app || {};
app.modules = app.modules || {};

var IO = function() {
	var self = this;
	self.io = app.io;
	self.io.fn._init();
}

app.modules['IO'] = IO;

app.io.fn = {

	handle: {

		iptraf: function(data) {
		/*
		 * Handle iptraf nodejs daemon "log output"
		 */

			var line = data.line;
			/* Run it through the normal parser */
			app.fn.parse_iptraf({ requester: 2, x: [data.line] });
line = {};
    	}, 

		pcap: function(data) {
			var packet = data.pkt;
	 		app.fn.parse_pcap({ requester: 2, x: [packet] });
packet = {};
		},

	},

	init_hooks: function() {

		app.io.socket.on("connect", function() {
		/*
		 * Resend our mode/type etc
		 */
			if(app.client.options.reconnect == 1) {
				for(var v in app.client.control) {
					var c = app.client.control[v];
					if(c.fn != undefined && c.fn._init != undefined) {
						c.fn._init();
					}
				}
			}
		});
		app.io.socket.on("reconnect", function() {
			app.client.options.reconnect = 1;
		});
	},


	_init: function() {


		if(app.client.io.options.reconnect > 0) { 
			return false;
		}

		app.io.options = {};


		/*
         * Nodejs support
         */
        if(typeof io != 'undefined') {
            app.io.njs = true;
            app.io.socket = io.connect(null);
			app.io.socket.on(app.DEFS.CHANNELS.IPTRAF, app.io.fn.handle.iptraf);
			app.io.socket.on(app.DEFS.CHANNELS.PCAP, app.io.fn.handle.pcap);
			app.io.fn.init_hooks();
        } else {
            app.io.njs = false;
            app.io.socket = {
				emit: function() { },
				on: function() { },
			};
        }
	},
}
