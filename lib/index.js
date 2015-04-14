/**
 * Module dependencies.
 */
var Strategy = require('./strategy');


/**
 * Expose `Strategy` directly from package.
 */
exports = module.exports = Strategy;

/**
 * Export constructors.
 */
exports.Strategy = Strategy;

exports.prepare = function(cb) {
  return function(req, options) {
    var passport = require('passport')

    passport.use('custom', new Strategy({
      authorizationURL: req.project.oauth.authenticationURL,
      tokenURL: req.project.oauth.tokenURL,
      clientID: req.project.oauth.clientID,
      clientSecret: req.project.oauth.clientSecret,
      userProfileURL: req.project.oauth.userProfileURL,
      callbackURL: req.project.base_url() + 'oauth/callback',
      special: req.project.oauth.special,
      accessTokenName: req.project.oauth.accessTokenName,
      passReqToCallback: true,
    }, cb));

    return passport.authenticate('custom', {
      //failureRedirect: '/hello'
      //session: false, // Turn this back on for "testing"
    }).apply(this, arguments);
  };
};
