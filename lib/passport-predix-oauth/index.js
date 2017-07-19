/**
 * Module dependencies.
 */
var PredixStrategy = require('./strategy');
var PasswordGrantStrategy = require('./passwordGrantStrategy');


/**
 * Framework version.
 */
require('pkginfo')(module, 'version');

/**
 * Expose constructors.
 */
exports.Strategy = PredixStrategy;
exports.Strategy = PasswordGrantStrategy;
