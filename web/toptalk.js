var app = app || {};
app.modules = app.modules || {};

var toptalk = function() {

	var self = this;
	self.toptalk = app.client.charts.toptalk;
	self.toptalk.fn._init();
}

app.modules['toptalk'] = toptalk;


	app.client.charts.toptalk.fn = {
	/* =================
	 * CHARTS => TOPTALK
	 * =================
	 */

		handle: {
			reset: function() {
				var tt = app.client.charts.toptalk;
				app.client.charts.fn.reset(tt.chart);
				app.client.tables.toptalk.data = {};
			},

			update: function(flow) {

				if(app.client.options.graphs == 0) {
					return false;
				}

				app.client.charts.toptalk.fn.handle.update_doit(flow);
			},

			update_override: function(flow) {
				app.client.charts.toptalk.fn.handle.update_doit(flow);
			},


			update_doit: function(flow) {


				/*
				 * update the top talker flows
				 */
				var tt = app.client.charts.toptalk;
				var series = tt.chart.series;

				if(series.length == 0 || series == undefined) {
					/*
					 * New series
					 */
					tt.chart.addSeries({
						name: flow.src,
						data: [ flow.total_bytes ]
					});
				} else {
                       
					for(var v = 0; v < series.length; v++) {
						/* update */

							if(v > 9) return false;

							if(series[v].name == flow.src) {
								series[v].setData([flow.total_bytes]);
								return true;
							}

							if(series[v].data[0] < flow.total_bytes) {
								series[v].remove();
								tt.chart.addSeries({
									name: flow.src,
									data: [ flow.total_bytes ],
								});
								return true;
							}
					}

					/* Means there is 9 or less series, this one doesn't already exist, so add it */
					tt.chart.addSeries({
						name: flow.src,
						data: [ flow.total_bytes ],
					});
				}
			},
		},

		_init: function() {

			var tt = app.client.charts.toptalk;

			tt.chart = app.client.charts.fn.build({
				type: "bar",
				container: tt.str.chart,
				title: "Top Talkers",
				subtitle: "A list of ip's using the most bandwidth",
				y_label: "Interfaces",
				x_label: "Bandwidth",
				series: []
			});

			$('body').delegate(tt.str.reset, 'click', tt.fn.handle.reset);
		},
	
	}
    
