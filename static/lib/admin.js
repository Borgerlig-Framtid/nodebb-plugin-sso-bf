define('admin/plugins/sso-bf', ['settings'], function(Settings) {
	'use strict';
	/* globals $, app, socket, require */

	var ACP = {};

	ACP.init = function() {
		Settings.load('sso-bf', $('.sso-bf-settings'));

		$('#save').on('click', function() {
			Settings.save('sso-bf', $('.sso-bf-settings'), function() {
				app.alert({
					type: 'success',
					alert_id: 'sso-bf-saved',
					title: 'Settings Saved',
					message: 'Please reload your NodeBB to apply these settings',
					clickfn: function() {
						socket.emit('admin.reload');
					}
				});
			});
		});
	};

	return ACP;
});