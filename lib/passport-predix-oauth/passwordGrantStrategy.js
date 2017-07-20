var util = require('util'),
    url = require('url'),
    InternalOAuthError = require('./internaloautherror'),
    OAuth2Strategy = require('passport-oauth').OAuth2Strategy;

function PasswordGrantStrategy(options, verify) {
    options = options || {};

    // We skip the auth-code step and do the basic authentication to get the token
    options.authorizationURL = '/';
    options.tokenURL = (options.uaaURL || options.tokenURL) + '/oauth/token';
    options.userProfileURL = options.uaaURL ? options.uaaURL + '/userinfo' : options.userProfileURL;

    //Send clientID & clientSecret in 'Authorization' header
    var auth = 'Basic ' + new Buffer(options.clientID + ':' + options.clientSecret).toString('base64');
    options.customHeaders = {
        'Authorization':auth
    };

    this._origCustomHeader = {
        'Authorization':auth
    };

    OAuth2Strategy.call(this, options, verify);

    this.name = 'predixPasswordGrantStrategy';

    this._oauth2.setAuthMethod('Bearer');

    // This is a "monkey patch" to fix the oauth2._executeRequest to work with a proxy.
    //  hopefully they'll fix this one day, in the oauth2 package.
    var originalExecuteRequest = this._oauth2._executeRequest;
    this._oauth2._executeRequest = function( http_library, options, post_body, callback ) {
        if (process.env['https_proxy']) {
            var whitelist = false;
            // Check the no_proxy env var for domains/hosts that should NOT use the proxy
            if(process.env['no_proxy']) {
                var nops = process.env['no_proxy'].split(',');
                for(var nop of nops) {
                    if(options.host.endsWith(nop)) {
                        whitelist = true;
                        break;
                    }
                }
            }

            if(!whitelist) {
                var HttpsProxyAgent = require('https-proxy-agent');
                options.agent = new HttpsProxyAgent(process.env['https_proxy']);
            }
        }
        return originalExecuteRequest( http_library, options, post_body, callback);
    };

    this._userProfileURI = options.userProfileURL;
}

/**
 * Authenticate request by delegating to a service provider using OAuth 2.0.
 *
 * @param {Object} req
 * @api protected
 */
PasswordGrantStrategy.prototype.authenticate = function(req, options) {
    options = options || {};
    var self = this;
    var uname=req.body.username;
    var pwd=req.body.password;

    if (req.query && req.query.error) {
      // TODO: Error information pertaining to OAuth 2.0 flows is encoded in the
      //       query parameters, and should be propagated to the application.
      return this.fail();
    }

    var callbackURL = options.callbackURL || this._callbackURL;
    if (callbackURL) {
      var parsed = url.parse(callbackURL);
      if (!parsed.protocol) {
        // The callback URL is relative, resolve a fully qualified URL from the
        // URL of the originating request.
        callbackURL = url.resolve(utils.originalURL(req), callbackURL);
      }
    }

      // NOTE: The module oauth (0.9.5), which is a dependency, automatically adds
      //       a 'type=web_server' parameter to the percent-encoded data sent in
      //       the body of the access token request.  This appears to be an
      //       artifact from an earlier draft of OAuth 2.0 (draft 22, as of the
      //       time of this writing).  This parameter is not necessary, but its
      //       presence does not appear to cause any issues.
      this._oauth2.getOAuthAccessToken('', { grant_type: 'password',username:uname,password:pwd, redirect_uri: callbackURL },
        function(err, accessToken, refreshToken, params) {
          if (err) { return self.error(new InternalOAuthError('failed to obtain access token', err)); }

          self._loadUserProfile(accessToken, function(err, profile) {
            if (err) { return self.error(err); };

            function verified(err, user, info) {
              if (err) { return self.error(err); }
              if (!user) { return self.fail(info); }
              self.success(user, info);
            }

            if (self._passReqToCallback) {
              var arity = self._verify.length;
              if (arity == 6) {
                self._verify(req, accessToken, refreshToken, params, profile, verified);
              } else { // arity == 5
                self._verify(req, accessToken, refreshToken, profile, verified);
              }
            } else {
              var arity = self._verify.length;
              if (arity == 5) {
                self._verify(accessToken, refreshToken, params, profile, verified);
              } else { // arity == 4
                self._verify(accessToken, refreshToken, profile, verified);
              }
            }
          });
        }
      );
}

util.inherits(PasswordGrantStrategy, OAuth2Strategy);


/**
 * Set user profile URI for a Cloud Foundry installation.
 * Default value: https://api.cloudfoundry.com/info
 *
 * @param {String} userProfileURI End-point to get user profile (/info in CF)
 */
PasswordGrantStrategy.prototype.setUserProfileURI = function (userProfileURI) {
    this._userProfileURI = userProfileURI;
};

/**
 * Resets _customHeaders to original _customHeaders - This is a workaround because of a
 * bug https://github.com/jaredhanson/passport/issues/89 that causes
 * "logout current user & then relogin to fail"
 *
 * Call this 'cfStrategy.reset()' when you are logging off a user.
 */
PasswordGrantStrategy.prototype.reset = function () {
    this._oauth2._customHeaders = {};
    this._oauth2._customHeaders['Authorization'] = this._origCustomHeader['Authorization'];
};

/**
 * Override authorizationParams function. In our case, we will check if this._stateParamCallback is
 * set. If so, we'll call that callback function to set {'state' : 'randomStateVal'}
 *
 * @param  {Object} options Hash of options
 * @return {Object}         {} or {'state' : 'randomStateValFrom__stateParamCallback'}
 */
PasswordGrantStrategy.prototype.authorizationParams = function(options) {
    if(this._stateParamCallback) {
        return {'state': this._stateParamCallback()};
    }
  return {};
};


PasswordGrantStrategy.prototype.setStateParamCallBack = function(callback) {
  this._stateParamCallback = callback;
};
/**
 * Expose `PasswordGrantStrategy`.
 */
module.exports = PasswordGrantStrategy;
