    powertips: function() {

    /*
     * TOOLTIPS!
     */

    /* total bytes */
        $('.f_tb').powerTip({
            placement: 'e',
            mouseOnToPopup: true
        });


        $('.f_tb').on({
            'powerTipPreRender': function(e) {
                var tr = e.target.id.replace(/_tot/g, '');
                tr = app.fn.reverse_table_key(tr);
                var flow = app.client.flows[tr];

                /*
                 * percent of cap: (tot / summary->tb_tot ) * 100
                 */

                var maths = {
                    percent_of_cap: (parseInt($('#'+e.target.id).text(),10) / app.client.summary[flow.iface].tot) * 100,
                }

                $(this).data('powertip' ,
                    '<h3 class="title">Traffic Summary</h3>'
                    +'<p>% of total: '+maths.percent_of_cap+'</p>'
                );

            },
      });


    /* total time */
        $('.f_tt').powerTip({
            placement: 'e',
            mouseOnToPopup: true
        });

        $('.f_tt').on({
            'powerTipPreRender': function(e) {
                var tr = e.target.id.replace(/_ts_tot/g, '');
                tr = app.fn.reverse_table_key(tr);
                var flow = app.client.flows[tr];

                var times = {
                    seconds: 0,
                    minutes: 0,
                    hours: 0,
                    days: 0,
                }

                /*
                 * seconds  = flows.ts_tot/1000
                 * minutes  = seconds/60
                 * hours    = minutes/24
                 * days     = hours/365.25
                 */
                times.seconds   = flow.ts_tot / 1000;
                times.minutes   = times.seconds / 60;
                times.hours     = times.minutes / 24;
                times.days      = times.hours / 365.25;

// TODO: round output to 2 dig
                $(this).data('powertip' ,
                        '<h3 class="title">Time Summary</h3>'
                    +'<p>'+times.seconds+' (s)</p>'
                    +'<p>'+times.minutes+' (m)</p>'
                    +'<p>'+times.hours+' (h)</p>'
                    +'<p>'+times.days+' (d)</p>'
                );
            },
        });

    },

 
