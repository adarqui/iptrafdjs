var app = app || {};
app.modules = app.modules || {};

var bandwidth = function() {

	var self = this;
	self.bw = app.client.charts.bandwidth;

	self.bw.fn._init();
}

app.modules['bandwidth'] = bandwidth;

	app.client.charts.bandwidth.fn = {
	/* ===================
	 * CHARTS => BANDWIDTH
	 * ===================
	 */

	handle: {

		io: function(data) {

			var bw = app.client.charts.bandwidth;

        	if(app.client.options.graphs == 0 || bw.chart == null) {
				return false; 
			}

			if(bw.interfaces == null) {

				bw.interfaces = _.clone(data.ifs);

            	var series_defined = [];

	            for(var v in data.ifs) {
                	bw.interfaces[v] = data.ifs[v].name;

                	series_defined.push({ name: data.ifs[v].name+"_tx", data: [], txrx: "tx" });
                	series_defined.push({ name: data.ifs[v].name+"_rx", data: [], txrx: "rx" });
            	}

				for(var v in series_defined) {
					bw.chart.addSeries(series_defined[v]);
				}

			}

        	for(var v in bw.chart.series) {

            	var iface_name_graph = bw.chart.series[v].name;
            	var iface_name = iface_name_graph.split('_')[0];

            	if(data.ifs[iface_name].rxA == 0 || data.ifs[iface_name].txA == 0) {
                	continue;
            	}

            	iface = data.ifs[iface_name];

            	var series = bw.chart.series[v];

				var shift = bw.inc > 10;

            	if(iface_name_graph.indexOf("tx")>0) {
                	var diff = data.ifs[iface_name].txB - data.ifs[iface_name].txA;
            	}
            	else {
                	var diff = data.ifs[iface_name].rxB - data.ifs[iface_name].rxA;
            	}


/* FORMULA FOR kb/s over 5 sec interval, need to send interval with data to make this formula work for intervals > or < than 5s */
	            diff = diff * .2; diff = diff / 100;

        	    bw.chart.series[v].addPoint([bw.inc, diff], true, shift)
	     		}

			bw.inc+=1;
		},


		save: function() {
			var bw = app.client.charts.bandwidth;
			var interval = $(bw.str.interval).val();
			app.io.socket.emit(app.DEFS.CHANNELS.BW, { interval: interval });
		},

		interval: function() {
			var bw = app.client.charts.bandwidth;
			$(bw.str.interval).val('');
		},

		reset: function() {
			var bw = app.client.charts.bandwidth;
			bw.interfaces = null;
			app.client.charts.fn.reset(bw.chart);
		},

	},

	_init: function() {

		var bw = app.client.charts.bandwidth;

		bw.chart = app.client.charts.fn.build({
			type: "spline",
			container: bw.str.chart,
			title: "Live bandwidth monitor",
			subtitle: "Monitor all interfaces on the system",
			y_label: "Interfaces",
			x_label: "Bandwidth",
			series: []
		});

		$('body').delegate(bw.str.interval, 'dblclick', bw.fn.handle.interval);
        
		$('body').delegate(bw.str.save, 'click', bw.fn.handle.save);

        $('body').delegate(bw.str.reset, 'click', bw.fn.handle.reset);

		app.io.socket.on(app.DEFS.CHANNELS.BW, bw.fn.handle.io);
	},

}
