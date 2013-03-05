var app = app || {};
app.modules = app.modules || {};

var misc = function() {
	var self = this;
	self.misc = app.misc;
}

app.modules['misc'] = misc;



app.misc.fn = {

	ip2long: function(ip) {
	// ripped
		if(ip == undefined) {
			return 0;
		}
		var ipl=0;
		ip.split('.').forEach(function( octet ) {
			ipl<<=8;
			ipl+=parseInt(octet);
		});
    	return(ipl >>>0);
	},

	long2ip: function(ipl) {
	// ripped
		if(ipl == undefined) {
			return 0;
		}
		return ( (ipl>>>24) +'.' +
			(ipl>>16 & 255) +'.' +
			(ipl>>8 & 255) +'.' +
			(ipl & 255) );
	},

	trav: function(data, fn) {
    $.each(data, function(x,y) {
            if (typeof y == 'object') {
                app.misc.fn.trav(y, fn);
            }
            else {
                fn(x, y);
            }
    	});
	},


}


$.fn.dataTableExt.oApi.fnFindCellRowIndexes = function ( oSettings, sSearch, iColumn )
{
    var
        i,iLen, j, jLen,
        aOut = [], aData;
      
    for ( i=0, iLen=oSettings.aoData.length ; i<iLen ; i++ )
    {
        aData = oSettings.aoData[i]._aData;
          
        if ( typeof iColumn == 'undefined' )
        {
            for ( j=0, jLen=aData.length ; j<jLen ; j++ )
            {
                if ( aData[j] == sSearch )
                {
                    aOut.push( i );
                }
            }
        }
        else if ( aData[iColumn] == sSearch )
        {
            aOut.push( i );
        }
    }
      
    return aOut;
};




// ripped
$.fn.togglepanels = function(){
  return this.each(function(){
    $(this).addClass("ui-accordion ui-accordion-icons ui-widget ui-helper-reset")
/* quick hack, get rid of h2's so jquery ui tabs can work properly, fix this later FIXME */
  .find("h1, h3")
    .addClass("ui-accordion-header ui-helper-reset ui-state-default ui-corner-top ui-corner-bottom graphsc")  
/*	.addClass("ui-accordion-header ui-state-default") */
    .hover(function() { $(this).toggleClass("ui-state-hover"); })
    .prepend('<span class="ui-icon ui-icon-triangle-1-e"></span>')
    .click(function() {
      $(this)
        .toggleClass("ui-accordion-header-active ui-state-active ui-state-default ui-corner-bottom")
        .find("> .ui-icon").toggleClass("ui-icon-triangle-1-e ui-icon-triangle-1-s").end()
        .next().slideToggle();
      return false;
    })
    .next()
      .addClass("ui-accordion-content ui-helper-reset ui-widget-content ui-corner-bottom")
    /*  .hide(); */ /* this opens all divs by default */
  });
};



$.fn.dataTableExt.oApi.fnStandingRedraw = function(oSettings) {
    if(oSettings.oFeatures.bServerSide === false){
        var before = oSettings._iDisplayStart;
 
        oSettings.oApi._fnReDraw(oSettings);
 
        // iDisplayStart has been reset to zero - so lets change it back
        oSettings._iDisplayStart = before;
        oSettings.oApi._fnCalculateEnd(oSettings);
    }
      
    // draw the 'current' page
    oSettings.oApi._fnDraw(oSettings);
};
