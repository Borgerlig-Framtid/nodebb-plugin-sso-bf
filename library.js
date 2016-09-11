(function(module) {
	'use strict';
	/* globals module, require */

	var user = module.parent.require('./user'),
		meta = module.parent.require('./meta'),
		db = module.parent.require('../src/database'),
		passport = module.parent.require('passport'),
		passportFacebook = require('passport-facebook').Strategy,
		nconf = module.parent.require('nconf'),
		async = module.parent.require('async'),
		winston = module.parent.require('winston');

	var authenticationController = module.parent.require('./controllers/authentication');

	var constants = Object.freeze({
		'name': 'Facebook',
		'admin': {
			'route': '/plugins/sso-bf',
			'icon': 'fa-facebook-square'
		}
	});

	var Facebook = {
		settings: undefined
	};

	Facebook.init = function(params, callback) {
		function render(req, res) {
			res.render('admin/plugins/sso-bf', {});
		}

		params.router.get('/admin/plugins/sso-bf', params.middleware.admin.buildHeader, render);
		params.router.get('/api/admin/plugins/sso-bf', render);

		callback();
	};

	Facebook.getSettings = function(callback) {
		if (Facebook.settings) {
			return callback();
		}

		meta.settings.get('sso-bf', function(err, settings) {
			Facebook.settings = settings;
			callback();
		});
	}

	Facebook.getStrategy = function(strategies, callback) {
		if (!Facebook.settings) {
			return Facebook.getSettings(function() {
				Facebook.getStrategy(strategies, callback);
			});
		}

		if (
			Facebook.settings !== undefined
			&& Facebook.settings.hasOwnProperty('app_id') && Facebook.settings.app_id
			&& Facebook.settings.hasOwnProperty('secret') && Facebook.settings.secret
		) {
			passport.use(new passportFacebook({
				clientID: Facebook.settings.app_id,
				clientSecret: Facebook.settings.secret,
				callbackURL: nconf.get('url') + '/auth/facebook/callback',
				passReqToCallback: true, profileFields: ['id', 'emails', 'name', 'displayName']
			}, function(req, accessToken, refreshToken, profile, done) {
				if (req.hasOwnProperty('user') && req.user.hasOwnProperty('uid') && req.user.uid > 0) {
					// Save facebook-specific information to the user
					user.setUserField(req.user.uid, 'fbid', profile.id);
					db.setObjectField('fbid:uid', profile.id, req.user.uid);

					return done(null, req.user);
				}

				var email;
				if (profile._json.hasOwnProperty('email')) {
					email = profile._json.email;
				} else {
					email = (profile.username ? profile.username : profile.id) + '@facebook.com';
				}

				Facebook.login(profile.id, profile.displayName, email, 'https://graph.facebook.com/' + profile.id + '/picture?type=large', accessToken, refreshToken, profile, function(err, user) {
					if (err) {
						return done(err);
					}


					authenticationController.onSuccessfulLogin(req, user.uid);
					done(null, user);
				});
			}));

			strategies.push({
				name: 'facebook',
				url: '/auth/facebook',
				callbackURL: '/auth/facebook/callback',
				icon: constants.admin.icon,
				scope: 'email, user_friends'
			});
		}

		callback(null, strategies);
	};

	Facebook.getAssociation = function(data, callback) {
		user.getUserField(data.uid, 'fbid', function(err, fbId) {
			if (err) {
				return callback(err, data);
			}

			if (fbId) {
				data.associations.push({
					associated: true,
					url: 'https://facebook.com/' + fbId,
					name: constants.name,
					icon: constants.admin.icon
				});
			} else {
				data.associations.push({
					associated: false,
					url: nconf.get('url') + '/auth/facebook',
					name: constants.name,
					icon: constants.admin.icon
				});
			}

			callback(null, data);
		})
	};


	Facebook.storeAdditionalData = function(userData, data, callback) {
		user.setUserField(userData.uid, 'email', data.email, callback);
	};

	Facebook.storeTokens = function(uid, accessToken, refreshToken) {
		//JG: Actually save the useful stuff
		winston.info("Storing received fb access information for uid(" + uid + ") accessToken(" + accessToken + ") refreshToken(" + refreshToken + ")");
		user.setUserField(uid, 'fbaccesstoken', accessToken);
		user.setUserField(uid, 'fbrefreshtoken', refreshToken);
	};

	Facebook.login = function(fbid, name, email, picture, accessToken, refreshToken, profile, callback) {

		winston.verbose("Facebook.login fbid, name, email, picture: " + fbid + ", " + ", " + name + ", " + email + ", " + picture);

		user.getUidByEmail(email, function (err, uid) {
			if (err) {
				return callback(err);
			}

			if (!uid) {
				return callback(new Error("[[error:Ditt FB-kontos e-mail matchar ingen existerande användare!]]"));
			}

				// Save their photo, if present
			user.getUserFields(uid, ['picture', 'uploadedpicture'], function (err, fieldData) {
				if (!err && picture && fieldData['uploadedpicture'] == '' && fieldData['picture'] == '') {
					user.setUserField(uid, 'uploadedpicture', picture);
					user.setUserField(uid, 'picture', picture);
				}
				return callback(null, { uid: uid });
			});
		});
	};

	Facebook.getUidByFbid = function(fbid, callback) {
		db.getObjectField('fbid:uid', fbid, function(err, uid) {

			if (err) {
				return callback(err);
			}
			callback(null, uid);
		});
	};

	Facebook.addMenuItem = function(custom_header, callback) {
		custom_header.authentication.push({
			'route': constants.admin.route,
			'icon': constants.admin.icon,
			'name': constants.name
		});

		callback(null, custom_header);
	};

	Facebook.deleteUserData = function(data, callback) {
		var uid = data.uid;

		async.waterfall([
			async.apply(user.getUserField, uid, 'fbid'),
			function(oAuthIdToDelete, next) {
				db.deleteObjectField('fbid:uid', oAuthIdToDelete, next);
			}
		], function(err) {
			if (err) {
				winston.error('[sso-bf] Could not remove OAuthId data for uid ' + uid + '. Error: ' + err);
				return callback(err);
			}
			callback(null, uid);
		});
	};

	module.exports = Facebook;
}(module));
