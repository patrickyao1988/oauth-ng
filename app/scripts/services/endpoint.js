'use strict';

var endpointClient = angular.module('oauth.endpoint', []);

endpointClient.factory('Endpoint', ['Storage', function(Storage) {

  var service = {};

  /*
   * Defines the authorization URL
   */

  service.set = function(configuration) {
    this.config = configuration;
    return this.get();
  };

  /*
   * Returns the authorization URL
   */

  service.get = function( overrides ) {
    var params = angular.extend( {}, service.config, overrides);
    var oAuthScope = (params.scope) ? encodeURIComponent(params.scope) : '',
        state = (params.state) ? encodeURIComponent(params.state) : '',
        authPathHasQuery = (params.authorizePath.indexOf('?') === -1) ? false : true,
        appendChar = (authPathHasQuery) ? '&' : '?',    //if authorizePath has ? already append OAuth2 params
        responseType = (params.responseType) ? encodeURIComponent(params.responseType) : '';

    var url = params.site +
          params.authorizePath +
          appendChar + 'response_type=' + responseType + '&' +
          'client_id=' + encodeURIComponent(params.clientId) + '&' +
          'redirect_uri=' + encodeURIComponent(params.redirectUri) + '&' +
          'scope=' + oAuthScope + '&' +
          'state=' + state;

    if( params.nonce ) {
      url = url + '&nonce=' + params.nonce;
    }
    return url;
  };

  /*
   * Redirects the app to the authorization URL
   */

  service.redirect = function( overrides ) {
    overrides = overrides || {};
    if (this.config.nonce) {
      var nonce = generateNonce();
      Storage.set('nonce', nonce);
      overrides.nonce = nonce;
    }
    var targetLocation = this.get( overrides );
    window.location.replace(targetLocation);
  };


  var generateNonce = function() {
    var crypto = window.crypto || window.msCrypto;
    //crypto.getRandomValues should be well supported nowadays, based on http://caniuse.com/#feat=getrandomvalues
    if (crypto && crypto.getRandomValues) {
      var array = new Uint32Array(1);
      crypto.getRandomValues(array);
      return array[0].toString(36);
    } else {
      var byteArrayToLong = function(byteArray) {
        var value = 0;
        for (var i = byteArray.length - 1; i >= 0; i--) {
          value = (value * 256) + byteArray[i];
        }
        return value;
      };
      var randArray= new Array(4);

      rng_seed_time();
      new SecureRandom().nextBytes(randArray);
      return byteArrayToLong(randArray).toString(36);
    }
  };


  return service;
}]);
