var app = app || {};
app.modules = app.modules || {};

var layout = function() {
	var self = this;
	self.layout = app.client.layout;
	self.layout.fn._init();
}

app.modules['layout'] = layout;


app.client.layout.fn = {

	init_portlets: function() {

     $('.column').sortable({
            connectWith: '.column',
			handle: '.portlet-header'
        });

        $('.portlet').addClass('ui-widget ui-widget-content ui-helper-clearfix ui-corner-all')
            .find('.portlet-header')
                .addClass('ui-widget-header ui-corner-all')
                .prepend('<span class="ui-icon ui-icon-minusthick"></span>')
                .end()
            .find('.portlet-content');
        $('.portlet-header .ui-icon').click(function() {
            $(this).toggleClass('ui-icon-minusthick').toggleClass('ui-icon-plusthick');
            $(this).parents('.portlet:first').find('.portlet-content').toggle();
        });

        $('.column').disableSelection();
	},

	_init: function() {

		// FIXME $(app.client.layout.accordion.str.output).togglepanels();

		app.client.layout.fn.init_portlets();
	}

}
