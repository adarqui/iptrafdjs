var app = app || {};
app.modules = app.modules || {};

var summary = function() {
	var self = this;
	self.summary = app.client.charts.summary;
	self.summary.fn._init();
}

app.modules['summary'] = summary;




	app.client.charts.summary.fn = {
	/* =================
	 * CHARTS => SUMMARY
	 * =================
	 */
		handle: {
			reset: function() {
				var s = app.client.charts.summary;
				app.client.charts.fn.reset(s.chart);
				app.client.tables.summary.data = {};
			},
			update: function(sum) {

				if(app.client.options.graphsc == 0) {
					return false;
				}

				/*
				 * update the summary column chart
				 */
				var s = app.client.charts.summary;
				var series = s.chart.series;

				if(series.length == 0 || series == undefined) {
					/*
					 * New series
					 */
					s.chart.addSeries({
						name: sum.iface,
						data: [ sum.tot ]
					});
				} else {
					/*
					 * update series
					 */
					for(var v in series) {
						if(series[v].name == sum.iface) {
							series[v].setData([sum.tot]);
						}
					}
					s.chart.redraw();
				}
			},
		},
		
		_init: function() {

			var s = app.client.charts.summary;

			s.chart = app.client.charts.fn.build({
				type: "column",
				container: s.str.chart,
				title: "General Interface Statstics",
				subtitle: "General statistcs - Interface view",
				y_label: "Bandwidth",
				x_label: "Interfaces",
				series: []
			});

			$('body').delegate(s.str.reset, 'click', s.fn.handle.reset);
		}

}
