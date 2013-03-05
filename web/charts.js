var app = app || {};
app.modules = app.modules || {};

var charts = function() {

    var self = this;
    self.charts = app.client.charts;

    self.charts.fn._init();
}

app.modules['charts'] = charts;
 

	app.client.charts.fn = {
	/*
	 * ===========================
	 * CHARTS => GENERIC FUNCTIONS
	 * ===========================
	 */
		click: function() {
//alert("graphs accordion clicked");
			app.client.options.graphs = (app.client.options.graphs > 0) ? app.client.options.graphs = 0 : app.client.options.graphs = 1;
//alert(app.client.options.graphs);
			if(app.client.options.graphs == 0) {
				$(app.client.charts.str.graphsc).text("Enable");
			}
			else if(app.client.options.graphs > 0 ) {
				$(app.client.charts.str.graphsc).text("Disable");
			}
		},

		reset: function(chart) {
			while(chart.series.length > 0) {
				var series = chart.series[0];
				series.remove(true);
			}
		},

		build: function(x) {
        /*
         * x.type {bar, column}
         * x.container
         * x.title
         * x.subtitle
         * x.categories
         * x.y_label
         * x.x_label
         * x.series
         */

        var chart;
        chart = new Highcharts.Chart({
            chart: {
                renderTo: x.container.replace(/#/g, ''),
                type: x.type,
            },
            title: {
                text: x.title,
            },
            subtitle: {
                text: x.subtitle,
            },
            xAxis: {
                categories: x.categories,
                title: {
                    text: null
                }
            },
            yAxis: {
                min: 0,
                title: {
                    text: x.y_label,
                    align: 'high'
 
                },
                labels: {
                    overflow: 'justify'
                }
            },
            plotOptions: {
                bar: {
                    dataLabels: {
                        enabled: true
                    }
                }
            },
            legend: {
                layout: 'vertical',
                align: 'right',
                verticalAlign: 'top',
                x: -100,
                y: 100,
                floating: true,
                borderWidth: 1,
                backgroundColor: '#FFFFFF',
                shadow: true
            },
            credits: {
                enabled: false
            },
            series: x.series,
                });

                return chart;
        },

		_init: function() {

			$(app.client.charts.str.graphs).tabs();

			$('body').delegate(app.client.charts.str.graphsc, "click", app.client.charts.fn.click);

		},

	}
