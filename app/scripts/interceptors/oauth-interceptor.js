'use strict';

var interceptorService = angular.module('oauth.interceptor', []);

interceptorService.factory('ExpiredInterceptor', ['Storage', '$rootScope', function (Storage, $rootScope) {

  var service = {};

  service.request = function(config) {
    var token = Storage.get('token');

    if (token) {
      if (expired(token)) {
        $rootScope.$broadcast('oauth:expired', token);
      } else { // TODO: Do we want to attach the token to every request ? or use the protected resource config ?
        config.headers.Authorization = 'Bearer ' + token.access_token;
      }
    }

    return config;
  };

  var expired = function(token) {
    return (token && token.expires_at && new Date(token.expires_at) < new Date());
  };

  return service;
}]);
