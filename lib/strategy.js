/**
 * Module dependencies.
 */
var util = require('util')
  , OAuth2Strategy = require('passport-oauth2')
  , Profile = require('./profile')
  , InternalOAuthError = require('passport-oauth2').InternalOAuthError;


/**
 * `Strategy` constructor.
 *
 * The GitHub authentication strategy authenticates requests by delegating to
 * GitHub using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your GitHub application's Client ID
 *   - `clientSecret`  your GitHub application's Client Secret
 *   - `callbackURL`   URL to which GitHub will redirect the user after granting authorization
 *   - `scope`         array of permission scopes to request.  valid scopes include:
 *                     'user', 'public_repo', 'repo', 'gist', or none.
 *                     (see http://developer.github.com/v3/oauth/#scopes for more info)
 *   — `userAgent`     All API requests MUST include a valid User Agent string.
 *                     e.g: domain name of your application.
 *                     (see http://developer.github.com/v3/#user-agent-required for more info)
 *
 * Examples:
 *
 *     passport.use(new GitHubStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/github/callback',
 *         userAgent: 'myapp.com'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  options = options || {};
  options.authorizationURL = options.authorizationURL;
  options.tokenURL = options.tokenURL;
  options.scope = options.scope;
  options.scopeSeparator = options.scopeSeparator || ',';
  options.customHeaders = options.customHeaders || {};

  console.log(options);

  if (!options.customHeaders['User-Agent']) {
    options.customHeaders['User-Agent'] = options.userAgent || 'passport-custom';
  }

  OAuth2Strategy.call(this, options, verify);
  this.name = 'custom';
  this._userProfileURL = options.userProfileURL;
  if(options.accessTokenName) {
    console.log('setting access', options.accessTokenName);
    this._oauth2.setAccessTokenName(options.accessTokenName);
  } else {
    this._oauth2.useAuthorizationHeaderforGET(true);
  }

  if(options.special === 'yammer') {
    // Despite claiming to support the OAuth 2.0 specification, Yammer's
    // implementation does anything but.  Yammer's token endpoint returns a
    // response that is so non-conformant that we are forced to resort to
    // extraordinary measures and override node-oauth's implmentation of
    // getOAuthAccessToken().
    this._oauth2.getOAuthAccessToken = function(code, params, callback) {
      var querystring = require('querystring');
      var params= params || {};
      params['client_id'] = this._clientId;
      params['client_secret'] = this._clientSecret;
      params['type']= 'web_server';
      params['code']= code;

      var post_data= querystring.stringify( params );
      var post_headers= {
        'Content-Type': 'application/x-www-form-urlencoded'
      };

      this._request("POST", this._getAccessTokenUrl(), post_headers, post_data, null, function(error, data, response) {
        if( error )  callback(error);
        else {
          var results;
          results= JSON.parse( data );
          var access_token= results["access_token"]["token"];
          callback(null, access_token);
        }
      });
    }
  }

  if(options.special === 'intercom') {
    this._oauth2.getOAuthAccessToken = function(code, params, callback) {
      var querystring = require('querystring');
      var params= params || {};
      params['client_id'] = this._clientId;
      params['client_secret'] = this._clientSecret;
      params['app_id']= 'lmc8lgvr';
      params['code']= code;

      var post_data= querystring.stringify( params );
      var post_headers= {
        'Content-Type': 'application/x-www-form-urlencoded',
        "Accept": "application/json",
        "Authorization": "Basic " + new Buffer(params['app_id'] + ":" + "6c6966d0c869d012d15a66ab8cf0127c2e2d7e7f").toString('base64'),
      };

      this._request("POST", this._getAccessTokenUrl(), post_headers, post_data, null, function(error, data, response) {
        if( error )  callback(error);
        else {
          var results;
          results= JSON.parse( data );
          var access_token= results["token"];
          callback(null, access_token);
        }
      });
    }

    this.userProfile = function(accessToken, done) {
      console.log("STRATEGY!");
      done(null, {
        email: 'gkoberger@gmail.com',
        name: 'Gregory Koberger',
        accessToken: accessToken,
      });
    }
  }
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);


/**
 * Retrieve user profile from GitHub.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `github`
 *   - `id`               the user's GitHub ID
 *   - `username`         the user's GitHub username
 *   - `displayName`      the user's full name
 *   - `profileUrl`       the URL of the profile for the user on GitHub
 *   - `emails`           the user's email addresses
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function(accessToken, done) {
  this._oauth2.get(this._userProfileURL, accessToken, function (err, body, res) {
    var json;
    
    if (err) {
      return done(new InternalOAuthError('Failed to fetch user profile', err));
    }
    
    try {
      json = JSON.parse(body);
    } catch (ex) {
      return done(new Error('Failed to parse user profile'));
    }
    
    var profile = Profile.parse(json);
    profile.provider  = 'custom';
    profile._raw = body;
    profile._json = json;
    
    done(null, profile);
  });
}


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
