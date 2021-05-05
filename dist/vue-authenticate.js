/**
 * vue-authenticate v1.5.9
 * https://github.com/dgrubelic/vue-authenticate
 * Released under the MIT License.
 * 
 */

(function (global, factory) {
  typeof exports === 'object' && typeof module !== 'undefined' ? module.exports = factory(require('crypto-js/sha256'), require('crypto-js/enc-base64'), require('crypto-js/lib-typedarrays')) :
  typeof define === 'function' && define.amd ? define(['crypto-js/sha256', 'crypto-js/enc-base64', 'crypto-js/lib-typedarrays'], factory) :
  (global = typeof globalThis !== 'undefined' ? globalThis : global || self, global.VueAuthenticate = factory(global.sha256, global.Base64, global.WordArray));
}(this, (function (sha256, Base64, WordArray) { 'use strict';

  function _interopDefaultLegacy (e) { return e && typeof e === 'object' && 'default' in e ? e : { 'default': e }; }

  var sha256__default = /*#__PURE__*/_interopDefaultLegacy(sha256);
  var Base64__default = /*#__PURE__*/_interopDefaultLegacy(Base64);
  var WordArray__default = /*#__PURE__*/_interopDefaultLegacy(WordArray);

  if (typeof Object.assign != 'function') {
    Object.assign = function (target, varArgs) {
      var arguments$1 = arguments;

      if (target == null) {
        throw new TypeError('Cannot convert undefined or null to object');
      }

      var to = Object(target);

      for (var index = 1; index < arguments.length; index++) {
        var nextSource = arguments$1[index];

        if (nextSource != null) {
          // Skip over if undefined or null
          for (var nextKey in nextSource) {
            // Avoid bugs when hasOwnProperty is shadowed
            if (Object.prototype.hasOwnProperty.call(nextSource, nextKey)) {
              to[nextKey] = nextSource[nextKey];
            }
          }
        }
      }
      return to;
    };
  }

  function camelCase(name) {
    return name.replace(/([\:\-\_]+(.))/g, function (
      _,
      separator,
      letter,
      offset
    ) {
      return offset ? letter.toUpperCase() : letter;
    });
  }

  function isUndefined(value) {
    return typeof value === 'undefined';
  }

  function isObject(value) {
    return value !== null && typeof value === 'object';
  }

  function isString(value) {
    return typeof value === 'string';
  }

  function isFunction(value) {
    return typeof value === 'function';
  }

  function objectExtend(a, b) {
    // Don't touch 'null' or 'undefined' objects.
    if (a == null || b == null) {
      return a;
    }

    Object.keys(b).forEach(function (key) {
      if (Object.prototype.toString.call(b[key]) == '[object Object]') {
        if (Object.prototype.toString.call(a[key]) != '[object Object]') {
          a[key] = b[key];
        } else {
          a[key] = objectExtend(a[key], b[key]);
        }
      } else {
        a[key] = b[key];
      }
    });

    return a;
  }

  /**
   * Assemble url from two segments
   *
   * @author Sahat Yalkabov <https://github.com/sahat>
   * @copyright Method taken from https://github.com/sahat/satellizer
   *
   * @param  {String} baseUrl Base url
   * @param  {String} url     URI
   * @return {String}
   */
  function joinUrl(baseUrl, url) {
    if (/^(?:[a-z]+:)?\/\//i.test(url)) {
      return url;
    }
    var joined = [baseUrl, url].join('/');
    var normalize = function (str) {
      return str
        .replace(/[\/]+/g, '/')
        .replace(/\/\?/g, '?')
        .replace(/\/\#/g, '#')
        .replace(/\:\//g, '://');
    };
    return normalize(joined);
  }

  /**
   * Get full path based on current location
   *
   * @author Sahat Yalkabov <https://github.com/sahat>
   * @copyright Method taken from https://github.com/sahat/satellizer
   *
   * @param  {Location} location
   * @return {String}
   */
  function getFullUrlPath(location) {
    var isHttps = location.protocol === 'https:';
    return (
      location.protocol +
      '//' +
      location.hostname +
      ':' +
      (location.port || (isHttps ? '443' : '80')) +
      (/^\//.test(location.pathname)
        ? location.pathname
        : '/' + location.pathname)
    );
  }

  /**
   * Parse query string variables
   *
   * @author Sahat Yalkabov <https://github.com/sahat>
   * @copyright Method taken from https://github.com/sahat/satellizer
   *
   * @param  {String} Query string
   * @return {String}
   */
  function parseQueryString(str) {
    var obj = {};
    var key;
    var value;
    (str || '').split('&').forEach(function (keyValue) {
      if (keyValue) {
        value = keyValue.split('=');
        key = decodeURIComponent(value[0]);
        obj[key] = !!value[1] ? decodeURIComponent(value[1]) : true;
      }
    });
    return obj;
  }

  /**
   * Decode base64 string
   * @author Sahat Yalkabov <https://github.com/sahat>
   * @copyright Method taken from https://github.com/sahat/satellizer
   *
   * @param  {String} str base64 encoded string
   * @return {Object}
   */
  function decodeBase64(str) {
    var buffer;
    if (typeof module !== 'undefined' && module.exports) {
      try {
        buffer = require('buffer').Buffer;
      } catch (err) {
        // noop
      }
    }

    var fromCharCode = String.fromCharCode;

    var re_btou = new RegExp(
      [
        '[\xC0-\xDF][\x80-\xBF]',
        '[\xE0-\xEF][\x80-\xBF]{2}',
        '[\xF0-\xF7][\x80-\xBF]{3}' ].join('|'),
      'g'
    );

    var cb_btou = function (cccc) {
      switch (cccc.length) {
        case 4:
          var cp =
            ((0x07 & cccc.charCodeAt(0)) << 18) |
            ((0x3f & cccc.charCodeAt(1)) << 12) |
            ((0x3f & cccc.charCodeAt(2)) << 6) |
            (0x3f & cccc.charCodeAt(3));
          var offset = cp - 0x10000;
          return (
            fromCharCode((offset >>> 10) + 0xd800) +
            fromCharCode((offset & 0x3ff) + 0xdc00)
          );
        case 3:
          return fromCharCode(
            ((0x0f & cccc.charCodeAt(0)) << 12) |
              ((0x3f & cccc.charCodeAt(1)) << 6) |
              (0x3f & cccc.charCodeAt(2))
          );
        default:
          return fromCharCode(
            ((0x1f & cccc.charCodeAt(0)) << 6) | (0x3f & cccc.charCodeAt(1))
          );
      }
    };

    var btou = function (b) {
      return b.replace(re_btou, cb_btou);
    };

    var _decode = buffer
      ? function (a) {
          return (a.constructor === buffer.constructor
            ? a
            : new buffer(a, 'base64')
          ).toString();
        }
      : function (a) {
          return btou(atob(a));
        };

    return _decode(
      String(str)
        .replace(/[-_]/g, function (m0) {
          return m0 === '-' ? '+' : '/';
        })
        .replace(/[^A-Za-z0-9\+\/]/g, '')
    );
  }

  function parseCookies(str) {
    if ( str === void 0 ) str = '';

    if (str.length === 0) { return {}; }
    var parsed = {};
    var pattern = new RegExp('\\s*;\\s*');
    str.split(pattern).forEach(function (i) {
      var ref = i.split('=');
      var encodedKey = ref[0];
      var encodedValue = ref[1];
      var key = decodeURIComponent(encodedKey);
      var value = decodeURIComponent(encodedValue);
      parsed[key] = value;
    });
    return parsed;
  }

  function formatOptions(options) {
    var path = options.path;
    var domain = options.domain;
    var expires = options.expires;
    var secure = options.secure;
    return [
      typeof path === 'undefined' || path === null ? '' : ';path=' + path,
      typeof domain === 'undefined' || domain === null ? '' : ';domain=' + domain,
      typeof expires === 'undefined' || expires === null
        ? ''
        : ';expires=' + expires.toUTCString(),
      typeof secure === 'undefined' || secure === null || secure === false
        ? ''
        : ';secure' ].join('');
  }

  function formatCookie(key, value, options) {
    return [
      encodeURIComponent(key),
      '=',
      encodeURIComponent(value),
      formatOptions(options) ].join('');
  }

  function getObjectProperty(objectRef, propertyName) {
    var value = undefined;
    var valueRef = objectRef;
    var propNames = propertyName.split('.');

    for (var i = 0; i < propNames.length; i++) {
      var key = propNames[i];
      value = valueRef[key];

      if (isObject(value)) {
        valueRef = valueRef[key];
      } else {
        break;
      }
    }

    return value;
  }

  function makeRequestOptions(requestOptions, options, urlName, user) {
    requestOptions = requestOptions || {};
    requestOptions.url = requestOptions.url || options.url || joinUrl(options.baseUrl, options.loginUrl);
    requestOptions[options.requestDataKey] =
      user || requestOptions[options.requestDataKey];
    requestOptions.method = requestOptions.method || 'POST';
    requestOptions.withCredentials =
      requestOptions.withCredentials || options.withCredentials;

    return requestOptions
  }

  function parseJWT(token) {
    var base64Url = token.split('.')[1];
    var base64 = base64Url.replace('-', '+').replace('_', '/');
    return JSON.parse(window.atob(base64));
  }

  // Store setTimeout reference so promise-polyfill will be unaffected by
  // other code modifying setTimeout (like sinon.useFakeTimers())
  var setTimeoutFunc = setTimeout;

  function noop() {}

  // Polyfill for Function.prototype.bind
  function bind(fn, thisArg) {
    return function () {
      fn.apply(thisArg, arguments);
    };
  }

  function Promise$1(fn) {
    if (typeof this !== 'object')
      { throw new TypeError('Promises must be constructed via new'); }
    if (typeof fn !== 'function') { throw new TypeError('not a function'); }
    this._state = 0;
    this._handled = false;
    this._value = undefined;
    this._deferreds = [];

    doResolve(fn, this);
  }

  function handle(self, deferred) {
    while (self._state === 3) {
      self = self._value;
    }
    if (self._state === 0) {
      self._deferreds.push(deferred);
      return;
    }
    self._handled = true;
    Promise$1._immediateFn(function () {
      var cb = self._state === 1 ? deferred.onFulfilled : deferred.onRejected;
      if (cb === null) {
        (self._state === 1 ? resolve : reject$1)(deferred.promise, self._value);
        return;
      }
      var ret;
      try {
        ret = cb(self._value);
      } catch (e) {
        reject$1(deferred.promise, e);
        return;
      }
      resolve(deferred.promise, ret);
    });
  }

  function resolve(self, newValue) {
    try {
      // Promise Resolution Procedure: https://github.com/promises-aplus/promises-spec#the-promise-resolution-procedure
      if (newValue === self)
        { throw new TypeError('A promise cannot be resolved with itself.'); }
      if (
        newValue &&
        (typeof newValue === 'object' || typeof newValue === 'function')
      ) {
        var then = newValue.then;
        if (newValue instanceof Promise$1) {
          self._state = 3;
          self._value = newValue;
          finale(self);
          return;
        } else if (typeof then === 'function') {
          doResolve(bind(then, newValue), self);
          return;
        }
      }
      self._state = 1;
      self._value = newValue;
      finale(self);
    } catch (e) {
      reject$1(self, e);
    }
  }

  function reject$1(self, newValue) {
    self._state = 2;
    self._value = newValue;
    finale(self);
  }

  function finale(self) {
    if (self._state === 2 && self._deferreds.length === 0) {
      Promise$1._immediateFn(function () {
        if (!self._handled) {
          Promise$1._unhandledRejectionFn(self._value);
        }
      });
    }

    for (var i = 0, len = self._deferreds.length; i < len; i++) {
      handle(self, self._deferreds[i]);
    }
    self._deferreds = null;
  }

  function Handler(onFulfilled, onRejected, promise) {
    this.onFulfilled = typeof onFulfilled === 'function' ? onFulfilled : null;
    this.onRejected = typeof onRejected === 'function' ? onRejected : null;
    this.promise = promise;
  }

  /**
   * Take a potentially misbehaving resolver function and make sure
   * onFulfilled and onRejected are only called once.
   *
   * Makes no guarantees about asynchrony.
   */
  function doResolve(fn, self) {
    var done = false;
    try {
      fn(
        function (value) {
          if (done) { return; }
          done = true;
          resolve(self, value);
        },
        function (reason) {
          if (done) { return; }
          done = true;
          reject$1(self, reason);
        }
      );
    } catch (ex) {
      if (done) { return; }
      done = true;
      reject$1(self, ex);
    }
  }

  Promise$1.prototype['catch'] = function (onRejected) {
    return this.then(null, onRejected);
  };

  Promise$1.prototype.then = function (onFulfilled, onRejected) {
    var prom = new this.constructor(noop);

    handle(this, new Handler(onFulfilled, onRejected, prom));
    return prom;
  };

  Promise$1.all = function (arr) {
    var args = Array.prototype.slice.call(arr);

    return new Promise$1(function (resolve, reject) {
      if (args.length === 0) { return resolve([]); }
      var remaining = args.length;

      function res(i, val) {
        try {
          if (val && (typeof val === 'object' || typeof val === 'function')) {
            var then = val.then;
            if (typeof then === 'function') {
              then.call(
                val,
                function (val) {
                  res(i, val);
                },
                reject
              );
              return;
            }
          }
          args[i] = val;
          if (--remaining === 0) {
            resolve(args);
          }
        } catch (ex) {
          reject(ex);
        }
      }

      for (var i = 0; i < args.length; i++) {
        res(i, args[i]);
      }
    });
  };

  Promise$1.resolve = function (value) {
    if (value && typeof value === 'object' && value.constructor === Promise$1) {
      return value;
    }

    return new Promise$1(function (resolve) {
      resolve(value);
    });
  };

  Promise$1.reject = function (value) {
    return new Promise$1(function (resolve, reject) {
      reject(value);
    });
  };

  Promise$1.race = function (values) {
    return new Promise$1(function (resolve, reject) {
      for (var i = 0, len = values.length; i < len; i++) {
        values[i].then(resolve, reject);
      }
    });
  };

  // Use polyfill for setImmediate for performance gains
  Promise$1._immediateFn =
    (typeof setImmediate === 'function' &&
      function (fn) {
        setImmediate(fn);
      }) ||
    function (fn) {
      setTimeoutFunc(fn, 0);
    };

  Promise$1._unhandledRejectionFn = function _unhandledRejectionFn(err) {
    if (typeof console !== 'undefined' && console) {
      console.warn('Possible Unhandled Promise Rejection:', err); // eslint-disable-line no-console
    }
  };

  /**
   * Set the immediate function to execute callbacks
   * @param fn {function} Function to execute
   * @deprecated
   */
  Promise$1._setImmediateFn = function _setImmediateFn(fn) {
    Promise$1._immediateFn = fn;
  };

  /**
   * Change the function to execute on unhandled rejection
   * @param {function} fn Function to execute on unhandled rejection
   * @deprecated
   */
  Promise$1._setUnhandledRejectionFn = function _setUnhandledRejectionFn(fn) {
    Promise$1._unhandledRejectionFn = fn;
  };

  var fakeDocument = {
    createElement: function createElement() { },
  };

  var fakeWindow = {
    atob: function atob() { },
    open: function open() { },
    location: {},
    localStorage: {
      setItem: function setItem() { },
      getItem: function getItem() { },
      removeItem: function removeItem() { },
    },
    sessionStorage: {
      setItem: function setItem() { },
      getItem: function getItem() { },
      removeItem: function removeItem() { },
    },
  };

  var $document = (typeof document !== 'undefined')
    ? document
    : fakeDocument;

  var $window = (typeof window !== 'undefined')
    ? window
    : fakeWindow;

  function getCookieDomainUrl() {
    try {
      return $window.location.hostname;
    } catch (e) {}

    return '';
  }

  function getRedirectUri(uri) {
    try {
      return !isUndefined(uri)
        ? ("" + ($window.location.origin) + uri)
        : $window.location.origin;
    } catch (e) {}

    return uri || null;
  }

  /**
   * Default configuration
   */
  var defaultOptions = {
    baseUrl: null,
    tokenPath: 'access_token',
    refreshTokenPath: 'refresh_token',
    tokenName: 'token',
    tokenPrefix: 'vueauth',
    tokenHeader: 'Authorization',
    tokenType: 'Bearer',
    expirationName: 'expiration',
    expirationPrefix: null,
    loginUrl: '/auth/login',
    registerUrl: '/auth/register',
    logoutUrl: null,
    refreshUrl: '/auth/login/refresh',
    storageType: 'localStorage',
    storageNamespace: 'vue-authenticate',
    cookieStorage: {
      domain: getCookieDomainUrl(),
      path: '/',
      secure: false,
    },
    requestDataKey: 'data',
    responseDataKey: 'data',
    last_token_refresh_attempt: null,

    refreshAuthFailInterceptors: [],

    /**
     * Default request interceptor for Axios library
     * @context {VueAuthenticate}
     */
    bindRequestInterceptor: null,
    bindResponseInterceptor: null,

    providers: {
      facebook: {
        name: 'facebook',
        url: '/auth/facebook',
        authorizationEndpoint: 'https://www.facebook.com/v2.5/dialog/oauth',
        redirectUri: getRedirectUri('/'),
        requiredUrlParams: ['display', 'scope'],
        scope: ['email'],
        scopeDelimiter: ',',
        display: 'popup',
        oauthType: '2.0',
        popupOptions: { width: 580, height: 400 },
      },

      google: {
        name: 'google',
        url: '/auth/google',
        authorizationEndpoint: 'https://accounts.google.com/o/oauth2/auth',
        redirectUri: getRedirectUri(),
        requiredUrlParams: ['scope'],
        optionalUrlParams: ['display'],
        scope: ['profile', 'email'],
        scopePrefix: 'openid',
        scopeDelimiter: ' ',
        display: 'popup',
        oauthType: '2.0',
        popupOptions: { width: 452, height: 633 },
      },

      github: {
        name: 'github',
        url: '/auth/github',
        authorizationEndpoint: 'https://github.com/login/oauth/authorize',
        redirectUri: getRedirectUri(),
        optionalUrlParams: ['scope'],
        scope: ['user:email'],
        scopeDelimiter: ' ',
        oauthType: '2.0',
        popupOptions: { width: 1020, height: 618 },
      },

      instagram: {
        name: 'instagram',
        url: '/auth/instagram',
        authorizationEndpoint: 'https://api.instagram.com/oauth/authorize',
        redirectUri: getRedirectUri(),
        requiredUrlParams: ['scope'],
        scope: ['basic'],
        scopeDelimiter: '+',
        oauthType: '2.0',
        popupOptions: { width: null, height: null },
      },

      twitter: {
        name: 'twitter',
        url: '/auth/twitter',
        authorizationEndpoint: 'https://api.twitter.com/oauth/authenticate',
        redirectUri: getRedirectUri(),
        oauthType: '1.0',
        popupOptions: { width: 495, height: 645 },
      },

      bitbucket: {
        name: 'bitbucket',
        url: '/auth/bitbucket',
        authorizationEndpoint: 'https://bitbucket.org/site/oauth2/authorize',
        redirectUri: getRedirectUri('/'),
        optionalUrlParams: ['scope'],
        scope: ['email'],
        scopeDelimiter: ' ',
        oauthType: '2.0',
        popupOptions: { width: 1020, height: 618 },
      },

      linkedin: {
        name: 'linkedin',
        url: '/auth/linkedin',
        authorizationEndpoint: 'https://www.linkedin.com/oauth/v2/authorization',
        redirectUri: getRedirectUri(),
        requiredUrlParams: ['state', 'scope'],
        scope: ['r_emailaddress'],
        scopeDelimiter: ' ',
        state: 'STATE',
        oauthType: '2.0',
        popupOptions: { width: 527, height: 582 },
      },

      live: {
        name: 'live',
        url: '/auth/live',
        authorizationEndpoint: 'https://login.live.com/oauth20_authorize.srf',
        redirectUri: getRedirectUri(),
        requiredUrlParams: ['display', 'scope'],
        scope: ['wl.emails'],
        scopeDelimiter: ' ',
        display: 'popup',
        oauthType: '2.0',
        popupOptions: { width: 500, height: 560 },
      },

      oauth1: {
        name: null,
        url: '/auth/oauth1',
        authorizationEndpoint: null,
        redirectUri: getRedirectUri(),
        oauthType: '1.0',
        popupOptions: null,
      },

      oauth2: {
        name: null,
        url: '/auth/oauth2',
        clientId: null,
        redirectUri: getRedirectUri(),
        authorizationEndpoint: null,
        defaultUrlParams: ['response_type', 'client_id', 'redirect_uri'],
        requiredUrlParams: null,
        optionalUrlParams: null,
        scope: null,
        scopePrefix: null,
        scopeDelimiter: null,
        state: null,
        oauthType: '2.0',
        popupOptions: null,
        responseType: 'code',
        responseParams: {
          code: 'code',
          clientId: 'clientId',
          redirectUri: 'redirectUri',
        },
      },
    },
  };

  var CookieStorage = function CookieStorage(defaultOptions) {
    this._defaultOptions = objectExtend(
      {
        domain: getCookieDomainUrl(),
        expires: null,
        path: '/',
        secure: false,
      },
      defaultOptions
    );
  };

  CookieStorage.prototype.setItem = function setItem (key, value) {
    var options = objectExtend({}, this._defaultOptions);
    var cookie = formatCookie(key, value, options);
    this._setCookie(cookie);
  };

  CookieStorage.prototype.getItem = function getItem (key) {
    var cookies = parseCookies(this._getCookie());
    return cookies.hasOwnProperty(key) ? cookies[key] : null;
  };

  CookieStorage.prototype.removeItem = function removeItem (key) {
    var value = '';
    var defaultOptions = objectExtend({}, this._defaultOptions);
    var options = objectExtend(defaultOptions, {
      expires: new Date(0),
    });
    var cookie = formatCookie(key, value, options);
    this._setCookie(cookie);
  };

  CookieStorage.prototype._getCookie = function _getCookie () {
    try {
      return $document.cookie === 'undefined' ? '' : $document.cookie;
    } catch (e) {}

    return '';
  };

  CookieStorage.prototype._setCookie = function _setCookie (cookie) {
    try {
      $document.cookie = cookie;
    } catch (e) {}
  };

  var LocalStorage = function LocalStorage(namespace) {
    this.namespace = namespace || null;
  };

  LocalStorage.prototype.setItem = function setItem (key, value) {
    $window.localStorage.setItem(this._getStorageKey(key), value);
  };

  LocalStorage.prototype.getItem = function getItem (key) {
    return $window.localStorage.getItem(this._getStorageKey(key));
  };

  LocalStorage.prototype.removeItem = function removeItem (key) {
    $window.localStorage.removeItem(this._getStorageKey(key));
  };

  LocalStorage.prototype._getStorageKey = function _getStorageKey (key) {
    if (this.namespace) {
      return [this.namespace, key].join('.');
    }
    return key;
  };

  var MemoryStorage = function MemoryStorage(namespace) {
    this.namespace = namespace || null;
    this._storage = {};
  };

  MemoryStorage.prototype.setItem = function setItem (key, value) {
    this._storage[this._getStorageKey(key)] = value;
  };

  MemoryStorage.prototype.getItem = function getItem (key) {
    return this._storage[this._getStorageKey(key)];
  };

  MemoryStorage.prototype.removeItem = function removeItem (key) {
    delete this._storage[this._getStorageKey(key)];
  };

  MemoryStorage.prototype._getStorageKey = function _getStorageKey (key) {
    if (this.namespace) {
      return [this.namespace, key].join('.');
    }
    return key;
  };

  var SessionStorage = function SessionStorage(namespace) {
    this.namespace = namespace || null;
  };

  SessionStorage.prototype.setItem = function setItem (key, value) {
    $window.sessionStorage.setItem(this._getStorageKey(key), value);
  };

  SessionStorage.prototype.getItem = function getItem (key) {
    return $window.sessionStorage.getItem(this._getStorageKey(key));
  };

  SessionStorage.prototype.removeItem = function removeItem (key) {
    $window.sessionStorage.removeItem(this._getStorageKey(key));
  };

  SessionStorage.prototype._getStorageKey = function _getStorageKey (key) {
    if (this.namespace) {
      return [this.namespace, key].join('.');
    }
    return key;
  };

  function StorageFactory(options) {
    switch (options.storageType) {
      case 'localStorage':
        try {
          $window.localStorage.setItem('testKey', 'test');
          $window.localStorage.removeItem('testKey');
          return new LocalStorage(options.storageNamespace);
        } catch (e) {}

      case 'sessionStorage':
        try {
          $window.sessionStorage.setItem('testKey', 'test');
          $window.sessionStorage.removeItem('testKey');
          return new SessionStorage(options.storageNamespace);
        } catch (e$1) {}

      case 'cookieStorage':
        return new CookieStorage(options.cookieStorage);

      case 'memoryStorage':
      default:
        return new MemoryStorage(options.storageNamespace);
    }
  }

  /**
   * OAuth2 popup management class
   *
   * @author Sahat Yalkabov <https://github.com/sahat>
   * @copyright Class mostly taken from https://github.com/sahat/satellizer
   * and adjusted to fit vue-authenticate library
   */
  var OAuthPopup = function OAuthPopup(url, name, popupOptions) {
    this.popup = null;
    this.url = url;
    this.name = name;
    this.popupOptions = popupOptions;
  };

  OAuthPopup.prototype.open = function open (redirectUri, skipPooling) {
    try {
      this.popup = $window.open(this.url, this.name, this._stringifyOptions());
      if (this.popup && this.popup.focus) {
        this.popup.focus();
      }

      if (skipPooling) {
        return Promise$1.resolve();
      } else {
        return this.pooling(redirectUri);
      }
    } catch (e) {
      return Promise$1.reject(new Error('OAuth popup error occurred'));
    }
  };

  OAuthPopup.prototype.pooling = function pooling (redirectUri) {
      var this$1 = this;

    return new Promise$1(function (resolve, reject) {
      var redirectUriParser = $document.createElement('a');
      redirectUriParser.href = redirectUri;
      var redirectUriPath = getFullUrlPath(redirectUriParser);

      var poolingInterval = setInterval(function () {
        if (
          !this$1.popup ||
          this$1.popup.closed ||
          this$1.popup.closed === undefined
        ) {
          clearInterval(poolingInterval);
          poolingInterval = null;
          reject(new Error('Auth popup window closed'));
        }

        try {
          var popupWindowPath = getFullUrlPath(this$1.popup.location);

          if (popupWindowPath === redirectUriPath) {
            if (this$1.popup.location.search || this$1.popup.location.hash) {
              var query = parseQueryString(
                this$1.popup.location.search.substring(1).replace(/\/$/, '')
              );
              var hash = parseQueryString(
                this$1.popup.location.hash.substring(1).replace(/[\/$]/, '')
              );
              var params = objectExtend({}, query);
              params = objectExtend(params, hash);

              if (params.error) {
                reject(new Error(params.error));
              } else {
                resolve(params);
              }
            } else {
              reject(
                new Error(
                  'OAuth redirect has occurred but no query or hash parameters were found.'
                )
              );
            }

            clearInterval(poolingInterval);
            poolingInterval = null;
            this$1.popup.close();
          }
        } catch (e) {
          // Ignore DOMException: Blocked a frame with origin from accessing a cross-origin frame.
        }
      }, 250);
    });
  };

  OAuthPopup.prototype._stringifyOptions = function _stringifyOptions () {
    var options = [];
    for (var optionKey in this.popupOptions) {
      if (!isUndefined(this.popupOptions[optionKey])) {
        options.push((optionKey + "=" + (this.popupOptions[optionKey])));
      }
    }
    return options.join(',');
  };

  var defaultProviderConfig$1 = {
    name: null,
    url: null,
    authorizationEndpoint: null,
    scope: null,
    scopePrefix: null,
    scopeDelimiter: null,
    redirectUri: null,
    requiredUrlParams: null,
    defaultUrlParams: null,
    oauthType: '1.0',
    popupOptions: {},
  };

  var OAuth = function OAuth($http, storage, providerConfig, options) {
    this.$http = $http;
    this.storage = storage;
    this.providerConfig = objectExtend({}, defaultProviderConfig$1);
    this.providerConfig = objectExtend(this.providerConfig, providerConfig);
    this.options = options;
  };

  /**
   * Initialize OAuth1 process
   * @param{Object} userData User data
   * @return {Promise}
   */
  OAuth.prototype.init = function init (userData) {
      var this$1 = this;

    this.oauthPopup = new OAuthPopup(
      'about:blank',
      this.providerConfig.name,
      this.providerConfig.popupOptions
    );

    if (!$window['cordova']) {
      this.oauthPopup.open(this.providerConfig.redirectUri, true);
    }

    return this.getRequestToken().then(function (response) {
      return this$1.openPopup(response).then(function (popupResponse) {
        return this$1.exchangeForToken(popupResponse, userData);
      });
    });
  };

  /**
   * Get OAuth1 request token
   * @return {Promise}
   */
  OAuth.prototype.getRequestToken = function getRequestToken () {
    var requestOptions = {};
    requestOptions.method = 'POST';
    requestOptions[this.options.requestDataKey] = objectExtend(
      {},
      this.providerConfig
    );
    requestOptions.withCredentials = this.options.withCredentials;
    if (this.options.baseUrl) {
      requestOptions.url = joinUrl(
        this.options.baseUrl,
        this.providerConfig.url
      );
    } else {
      requestOptions.url = this.providerConfig.url;
    }

    return this.$http(requestOptions);
  };

  /**
   * Open OAuth1 popup
   * @param{Object} response Response object containing request token
   * @return {Promise}
   */
  OAuth.prototype.openPopup = function openPopup (response) {
    var url = [
      this.providerConfig.authorizationEndpoint,
      this.buildQueryString(response[this.options.responseDataKey]) ].join('?');

    this.oauthPopup.popup.location = url;
    if ($window['cordova']) {
      return this.oauthPopup.open(this.providerConfig.redirectUri);
    } else {
      return this.oauthPopup.pooling(this.providerConfig.redirectUri);
    }
  };

  /**
   * Exchange token and token verifier for access token
   * @param{Object} oauth  OAuth data containing token and token verifier
   * @param{Object} userData User data
   * @return {Promise}
   */
  OAuth.prototype.exchangeForToken = function exchangeForToken (oauth, userData) {
    var payload = objectExtend({}, userData);
    payload = objectExtend(payload, oauth);
    var requestOptions = {};
    requestOptions.method = 'POST';
    requestOptions[this.options.requestDataKey] = payload;
    requestOptions.withCredentials = this.options.withCredentials;
    if (this.options.baseUrl) {
      requestOptions.url = joinUrl(
        this.options.baseUrl,
        this.providerConfig.url
      );
    } else {
      requestOptions.url = this.providerConfig.url;
    }
    return this.$http(requestOptions);
  };

  OAuth.prototype.buildQueryString = function buildQueryString (params) {
    var parsedParams = [];
    for (var key in params) {
      var value = params[key];
      parsedParams.push(
        encodeURIComponent(key) + '=' + encodeURIComponent(value)
      );
    }
    return parsedParams.join('&');
  };

  /**
   * Default provider configuration
   * @type {Object}
   */
  var defaultProviderConfig = {
    name: null,
    url: null,
    clientId: null,
    authorizationEndpoint: null,
    redirectUri: null,
    scope: null,
    scopePrefix: null,
    scopeDelimiter: null,
    state: null,
    requiredUrlParams: null,
    defaultUrlParams: ['response_type', 'client_id', 'redirect_uri'],
    responseType: 'code',
    responseGrantType: 'authorization_code',
    refreshGrantType: "refresh_token",  // There are three types of refresh tokens,
    // 1. (httponly): refresh token is set via HttpOnly Cookie which is the safest method
    // 2. (storage): refresh token is safe in the local storage, which is as safe as just send a long life access_token
    // 3. (null): refresh token is not use
    refreshType: null,
    refreshTokenPrefix: null,
    tokenRequestAsForm: false,
    refreshRequestAsForm: false,
    pkce: false,
    responseParams: {
      code: 'code',
      clientId: 'clientId',
      redirectUri: 'redirectUri',
    },
    refreshParams: {
      clientId: 'clientId',
      grantType: 'grantType',
      scope: 'scope'
    },
    oauthType: '2.0',
    popupOptions: {},
  };

  var OAuth2 = function OAuth2($http, storage, providerConfig, options) {
    this.$http = $http;
    this.storage = storage;
    this.providerConfig = objectExtend({}, defaultProviderConfig);
    this.providerConfig = objectExtend(this.providerConfig, providerConfig);
    this.options = options;
  };

  OAuth2.prototype.generateRandomForKey = function generateRandomForKey (key) {
    if(!this.storage.getItem(key)) {
      this.storage.setItem(key, WordArray__default['default'].random(64));
    }

    console.log(this.storage.getItem(key));
    return this.storage.getItem(key);
  };

  OAuth2.prototype.init = function init (userData) {
      var this$1 = this;

    var stateName = this.providerConfig.name + '_state';
    if (isFunction(this.providerConfig.state)) {
      this.storage.setItem(stateName, this.providerConfig.state());
    } else if (isString(this.providerConfig.state)) {
      this.storage.setItem(stateName, this.providerConfig.state);
    }

    var url = [
      this.providerConfig.authorizationEndpoint,
      this._stringifyRequestParams() ].join('?');


    if(this.providerConfig.pkce === 'S256'){
      if(this.providerConfig.responseType !== 'code'){
        throw new Error(("Cannot use PKCE with response type " + (this.providerConfig.responseType)));
      }
      var hashed = sha256__default['default'](this.generateRandomForKey(this.providerConfig.name + '_pkce'));
      var pkce_challenge = Base64__default['default'].stringify(hashed).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

      url = url + "&code_challenge=" + (encodeURIComponent(pkce_challenge)) + "&code_challenge_method=S256";
    }

    this.oauthPopup = new OAuthPopup(
      url,
      this.providerConfig.name,
      this.providerConfig.popupOptions
    );

    return new Promise$1(function (resolve, reject) {
      this$1.oauthPopup
        .open(this$1.providerConfig.redirectUri)
        .then(function (response) {
          if (
            this$1.providerConfig.responseType === 'token' ||
            !this$1.providerConfig.url
          ) {
            return resolve(response);
          }

          if (
            response.state &&
            response.state !== this$1.storage.getItem(stateName)
          ) {
            return reject(
              new Error(
                'State parameter value does not match original OAuth request state value'
              )
            );
          }

          this$1.exchangeForToken(response, userData).then(function (response){
            this$1.storage.removeItem(this$1.providerConfig.name + '_pkce');
            return response.data;
          }).then(resolve);
        })
        .catch(function (err) {
          reject(err);
        });
    });
  };

  /**
   * Exchange temporary oauth data for access token
   * @author Sahat Yalkabov <https://github.com/sahat>
   * @copyright Method taken from https://github.com/sahat/satellizer
   *
   * @param{[type]} oauth  [description]
   * @param{[type]} userData [description]
   * @return {[type]}        [description]
   */
  OAuth2.prototype.exchangeForToken = function exchangeForToken (oauth, userData) {
    var payload = objectExtend({}, userData);

    for (var key in this.providerConfig.responseParams) {
      var value = this.providerConfig.responseParams[key];

      switch (key) {
        case 'code':
          payload[value] = oauth.code;
          break
        case 'clientId':
          payload[value] = this.providerConfig.clientId;
          break
        case 'redirectUri':
          payload[value] = this.providerConfig.redirectUri;
          break
        case 'grantType':
          payload[value] = this.providerConfig.responseGrantType;
          break
        default:
          payload[value] = oauth[key];
      }
    }

    if (oauth.state) {
      payload.state = oauth.state;
    }

    var exchangeTokenUrl;
    if (this.options.baseUrl) {
      exchangeTokenUrl = joinUrl(this.options.baseUrl, this.providerConfig.url);
    } else {
      exchangeTokenUrl = this.providerConfig.url;
    }

    if(this.providerConfig.pkce){
      var pkceVerifier = this.storage.getItem(this.providerConfig.name + '_pkce');
      if(pkceVerifier){
        payload['code_verifier'] = pkceVerifier;
        payload['grant_type'] = 'authorization_code';
        console.log(pkceVerifier);
      }
    }

    if(this.providerConfig.tokenRequestAsForm){
      var form = new FormData();
      for (var key$1 in payload) {
        var value$1 = payload[key$1];
        form.append(key$1, value$1);
      }
      payload = form;
    }

    return this.$http.post(exchangeTokenUrl, payload, {
      withCredentials: this.options.withCredentials,
    });
  };

  /**
   * Stringify oauth params
   * @author Sahat Yalkabov <https://github.com/sahat>
   * @copyright Method taken from https://github.com/sahat/satellizer
   *
   * @return {String}
   */
  OAuth2.prototype._stringifyRequestParams = function _stringifyRequestParams () {
      var this$1 = this;

    var keyValuePairs = [];
    var paramCategories = [
      'defaultUrlParams',
      'requiredUrlParams',
      'optionalUrlParams' ];

    paramCategories.forEach(function (categoryName) {
      if (!this$1.providerConfig[categoryName]) { return; }
      if (!Array.isArray(this$1.providerConfig[categoryName])) { return; }

      this$1.providerConfig[categoryName].forEach(function (paramName) {
        var camelCaseParamName = camelCase(paramName);
        var paramValue = isFunction(this$1.providerConfig[paramName])
          ? this$1.providerConfig[paramName]()
          : this$1.providerConfig[camelCaseParamName];

        if (paramName === 'redirect_uri' && !paramValue) { return; }

        if (paramName === 'state') {
          var stateName = this$1.providerConfig.name + '_state';
          paramValue = encodeURIComponent(this$1.storage.getItem(stateName));
        }
        if (paramName === 'scope' && Array.isArray(paramValue)) {
          paramValue = paramValue.join(this$1.providerConfig.scopeDelimiter);
          if (this$1.providerConfig.scopePrefix) {
            paramValue = [this$1.providerConfig.scopePrefix, paramValue].join(
              this$1.providerConfig.scopeDelimiter
            );
          }
        }

        keyValuePairs.push([paramName, paramValue]);
      });
    });

    return keyValuePairs
      .map(function (param) {
        return param.join('=');
      })
      .join('&');
  };

  /**
   * Get refresh token
   * @returns {String|null} refresh token
   */
  OAuth2.prototype.getRefreshToken = function getRefreshToken (name) {
    if (this.options.refreshType === 'storage')
      { return this.storage.getItem(name) }

    return null;
  };

  /**
   * Refresh access token
   * @param requestOptionsRequest options
   * @returns {Promise}   Request Promise
   */
  OAuth2.prototype.refresh = function refresh (refreshTokenName) {
    if (!this.options.storageType) {
      throw new Error('Refreshing is not set');
    }

    var data = {};

    if (this.options.refreshType === 'storage')
      { data.refresh_token = this.getRefreshToken(refreshTokenName); }

    for (var key in this.providerConfig.refreshParams) {
      var value = this.providerConfig.refreshParams[key];

      switch (key) {
        case 'clientId':
          data[value] = this.providerConfig.clientId;
          break
        case 'grantType':
          data[value] = this.providerConfig.refreshGrantType;
          break
        default:
          data[value] = this.providerConfig[key];
      }
    }

    if (this.providerConfig.refreshRequestAsForm) {
      var form = new FormData();
      for (var key$1 in data) {
        var value$1 = data[key$1];

        form.set(key$1, value$1);
      }

      data = form;
    }

    var requestOptions = makeRequestOptions(this.providerConfig, this.options, 'refreshUrl', data);
    return this.$http(requestOptions);
  };

  var VueAuthenticate = function VueAuthenticate($http, overrideOptions) {
    var options = objectExtend({}, defaultOptions);
    options = objectExtend(options, overrideOptions);
    var storage = StorageFactory(options);

    Object.defineProperties(this, {
      $http: {
        get: function get() {
          return $http;
        },
      },

      options: {
        get: function get() {
          return options;
        },
      },

      storage: {
        get: function get() {
          return storage;
        },
      },

      tokenName: {
        get: function get() {
          if (this.options.tokenPrefix) {
            return [this.options.tokenPrefix, this.options.tokenName].join('_');
          } else {
            return this.options.tokenName;
          }
        }
      },

      refreshTokenName: {
        get: function get() {
          if (this.options.refreshTokenPrefix) {
            return [this.options.refreshTokenPrefix, this.options.refreshTokenName].join('_')
          } else {
            return this.options.refreshTokenName
          }
        }
      },

      expirationName: {
        get: function get() {
          if (this.options.expirationPrefix) {
            return [this.options.expirationPrefix, this.options.expirationName].join('_')
          } else {
            return this.options.expirationName
          }
        }
      }
    });

    // Setup request interceptors
    if (this.options.bindRequestInterceptor) {
      if (isFunction(this.options.bindRequestInterceptor)){
        this.options.bindRequestInterceptor.call(this, this);
      }else {
        throw new Error('Request interceptor must be functions');
      }
    } else {
      this.defaultBindRequestInterceptor(this, this);
    }

    // Setup response interceptors
    if (this.options.bindResponseInterceptor) {
      if(isFunction(this.options.bindResponseInterceptor)){
        this.options.bindResponseInterceptor.call(this, this);
      }else {
        throw new Error('Response interceptor must be functions')
      }
    } else {
      this.defaultBindResponseInterceptor(this, this);
    }
  };

  /**
   * Check if user is authenticated
   * @author Sahat Yalkabov <https://github.com/sahat>
   * @copyright Method taken from https://github.com/sahat/satellizer
   * @return {Boolean}
   */
  VueAuthenticate.prototype.isAuthenticated = function isAuthenticated () {
    var token = this.storage.getItem(this.tokenName);

    if (token) {
      // Token is present
      if (token.split('.').length === 3) {
        // Token with a valid JWT format XXX.YYY.ZZZ
        try {
          // Could be a valid JWT or an access token with the same format
          var exp = parseJWT(token).exp;
          if (typeof exp === 'number') {
            // JWT with an optional expiration claims
            return Math.round(new Date().getTime() / 1000) < exp;
          }
        } catch (e) {
          return true; // Pass: Non-JWT token that looks like JWT
        }
      }
      return true; // Pass: All other tokens
    }
    return false;
  };

  /**
   * Returns if a token is set
   * @returns {boolean}
   */
  VueAuthenticate.prototype.isTokenSet = function isTokenSet () {
    if (isUndefined(this.getToken())) { return false; }
    return !!this.getToken()
  };

  /**
   * Get token if user is authenticated
   * @return {String} Authentication token
   */
  VueAuthenticate.prototype.getToken = function getToken () {
    return this.storage.getItem(this.tokenName);
  };

  /**
   * Set new authentication token
   * @param {String|Object} response
   */
  VueAuthenticate.prototype.setToken = function setToken (response, tokenPath) {
    if (response[this.options.responseDataKey]) {
      response = response[this.options.responseDataKey];
    }

    var responseTokenPath = tokenPath || this.options.tokenPath;
    var token = getObjectProperty(response, responseTokenPath);

    if (token) {
      this.storage.setItem(this.tokenName, token);
    }
  };

  /**
   * Get the logged in provider
   * @return {String} provider
   */
  VueAuthenticate.prototype.getLoggedInProvider = function getLoggedInProvider () {
    return this.storage.getItem('LoggedInProvider');
  };

  /**
   * Set logged in provider
   * @param {String} provider
   */
  VueAuthenticate.prototype.setLoggedInProvider = function setLoggedInProvider (provider) {
      this.storage.setItem('LoggedInProvider', provider);
  };

  /**
   * Get expiration of the access token
   * @returns {number|null} expiration
   */
  VueAuthenticate.prototype.getExpiration = function getExpiration () {
    if (this.options.refreshType)
      { return this.storage.getItem(this.expirationName) }
    return null;
  };

  /**
   * Set new refresh token
   * @param {String|Object} response
   * @param {String} tokenPath
   * @returns {String|Object} response
   */
  VueAuthenticate.prototype.setRefreshToken = function setRefreshToken (response, tokenPath) {
    // Check if refresh token is required
    if (!this.options.refreshType) {
      return;
    }

    if (response[this.options.responseDataKey]) {
      response = response[this.options.responseDataKey];
    }

    this.setExpiration(response);
    // set refresh token if it's not provided over a HttpOnly cookie
    if (!(this.options.refreshType === 'storage')) {
      return response;
    }

    var refreshTokenPath = tokenPath || this.options.refreshTokenPath;
    var refresh_token = getObjectProperty(response, refreshTokenPath);

    if (!refresh_token && response) {
      refresh_token = response[this.options.expirationName];
    }

    if (refresh_token) {
      this.storage.setItem(this.refreshTokenName, refresh_token);
    }

    return response
  };

  /**
   * Sets the expiration of the access token
   * @param {String|Object} response
   * @returns {String|Object} response
   */
  VueAuthenticate.prototype.setExpiration = function setExpiration (response) {
    // set expiration of access token
    var expiration;
    if (response.expires_in) {
      var expires_in = parseInt(response.expires_in);
      if (isNaN(expires_in)) { expires_in = 0; }
      expiration = Math.round(new Date().getTime() / 1000) + expires_in;
    }

    if (!expiration && response) {
      var expires_in$1 = parseInt(response[this.options.expirationName]);
      if (isNaN(expires_in$1)) { expires_in$1 = 0; }
      expiration = Math.round(new Date().getTime() / 1000) + expires_in$1;
    }

    if (expiration) {
      this.storage.setItem(this.expirationName, expiration);
    }

    return response
  };


  VueAuthenticate.prototype.getPayload = function getPayload () {
    var token = this.storage.getItem(this.tokenName);

    if (token && token.split('.').length === 3) {
      try {
        var base64Url = token.split('.')[1];
        var base64 = base64Url.replace('-', '+').replace('_', '/');
        return JSON.parse(decodeBase64(base64));
      } catch (e) {
      }
    }
  };

  /**
   * Login user using email and password
   * @param{Object} user         User data
   * @param{Object} requestOptions Request options
   * @return {Promise}             Request promise
   */
  VueAuthenticate.prototype.login = function login (user, requestOptions) {
      var this$1 = this;

    requestOptions = makeRequestOptions(requestOptions, this.options, 'loginUrl', user);

    return this.$http(requestOptions)
      .then(function (response) {
        this$1.setToken(response);
        this$1.setRefreshToken(response);
        // Check if we are authenticated
        if(this$1.isAuthenticated()){
          return Promise$1.resolve(response);
        }
        throw new Error('Server did not provided an access token.');
      })
      .catch(function (error) {
        return Promise$1.reject(error)
      })
  };

  /**
   * Register new user
   * @param{Object} user         User data
   * @param{Object} requestOptions Request options
   * @return {Promise}             Request promise
   */
  VueAuthenticate.prototype.register = function register (user, requestOptions) {
      var this$1 = this;

    requestOptions = makeRequestOptions(requestOptions, this.options, 'registerUrl', user);

    return this.$http(requestOptions)
      .then(function (response) {
        this$1.setToken(response);
        this$1.setRefreshToken(response);
        return Promise$1.resolve(response);
      })
      .catch(function (err) { return Promise$1.reject(err); })
  };

  /**
   * Logout current user
   * @param{Object} requestOptionsLogout request options object
   * @return {Promise}              Request promise
   */
  VueAuthenticate.prototype.logout = function logout (requestOptions) {
      var this$1 = this;

    if (!this.isAuthenticated()) {
      return Promise$1.reject(
        new Error('There is no currently authenticated user')
      );
    }

    requestOptions = requestOptions || {};

    if (requestOptions.url || this.options.logoutUrl) {
      requestOptions.url = requestOptions.url
        ? requestOptions.url
        : joinUrl(this.options.baseUrl, this.options.logoutUrl);
      requestOptions.method = requestOptions.method || 'POST';
      requestOptions[this.options.requestDataKey] =
        requestOptions[this.options.requestDataKey] || undefined;
      requestOptions.withCredentials =
        requestOptions.withCredentials || this.options.withCredentials;

      return this.$http(requestOptions)
        .then(function (response) {
          this$1.storage.removeItem(this$1.tokenName);
          return Promise$1.resolve(response);
        })
        .catch(function (err) { return Promise$1.reject(err); })
    } else {
      this.storage.removeItem(this.tokenName);
      return Promise$1.resolve();
    }
  };

  /**
   * Refresh access token
   * @param requestOptionsRequest options
   * @returns {Promise}   Request Promise
   */
  VueAuthenticate.prototype.refresh = function refresh () {
      var this$1 = this;

    var provider = this.getLoggedInProvider();
    var providerConfig = this.options.providers[provider];
    var refreshTokenName = this.refreshTokenName;

    if (!providerConfig) {
      return reject(new Error('Unknown provider'));
    }

    var providerInstance;
    switch (providerConfig.oauthType) {
      case '2.0':
        providerInstance = new OAuth2(
          this.$http,
          this.storage,
          providerConfig,
          this.options
        );
        break;
      default:
        return reject(new Error('Invalid OAuth type for refresh'));
    }

    return providerInstance
      .refresh(refreshTokenName)
      .then(function (response) {
        this$1.setToken(response);
        this$1.setRefreshToken(response);
        return response;
      })
      .catch(function (error) {
        this$1.clearStorage();
        throw error;
      })
  };

  /**
   * Remove all item from the storage
   */
  VueAuthenticate.prototype.clearStorage = function clearStorage () {
    this.storage.removeItem(this.tokenName);
    this.storage.removeItem(this.expirationName);
    this.storage.removeItem(this.refreshTokenName);
  };

  /**
   * Authenticate user using authentication provider
   *
   * @param{String} provider     Provider name
   * @param{Object} userData     User data
   * @return {Promise}             Request promise
   */
  VueAuthenticate.prototype.authenticate = function authenticate (provider, userData) {
      var this$1 = this;

    return new Promise$1(function (resolve, reject) {
      var providerConfig = this$1.options.providers[provider];
      if (!providerConfig) {
        return reject(new Error('Unknown provider'));
      }

      var providerInstance;
      switch (providerConfig.oauthType) {
        case '1.0':
          providerInstance = new OAuth(
            this$1.$http,
            this$1.storage,
            providerConfig,
            this$1.options
          );
          break;
        case '2.0':
          providerInstance = new OAuth2(
            this$1.$http,
            this$1.storage,
            providerConfig,
            this$1.options
          );
          break;
        default:
          return reject(new Error('Invalid OAuth type'));
      }

      return providerInstance
        .init(userData)
        .then(function (response) {
          this$1.setToken(response, providerConfig.tokenPath);
          this$1.setRefreshToken(response, providerConfig.refreshTokenPath);
          this$1.setLoggedInProvider(provider);

          if (this$1.isAuthenticated()) {
            return resolve(response);
          } else {
            return reject(new Error('Authentication failed'));
          }
        })
        .catch(function (err) { return reject(err); });
    });
  };

  /**
   * Link user using authentication provider without login
   *
   * @param{String} provider     Provider name
   * @param{Object} userData     User data
   * @return {Promise}             Request promise
   */
  VueAuthenticate.prototype.link = function link (provider, userData) {
      var this$1 = this;

    return new Promise$1(function (resolve, reject) {
      var providerConfig = this$1.options.providers[provider];
      if (!providerConfig) {
        return reject(new Error('Unknown provider'));
      }

      var providerInstance;
      switch (providerConfig.oauthType) {
        case '1.0':
          providerInstance = new OAuth(
            this$1.$http,
            this$1.storage,
            providerConfig,
            this$1.options
          );
          break;
        case '2.0':
          providerInstance = new OAuth2(
            this$1.$http,
            this$1.storage,
            providerConfig,
            this$1.options
          );
          break;
        default:
          return reject(new Error('Invalid OAuth type'));
      }

      return providerInstance
        .init(userData)
        .then(function (response) {
          if (response[this$1.options.responseDataKey]) {
            response = response[this$1.options.responseDataKey];
          }

          resolve(response);
        })
        .catch(reject);
    });
  };

  /**
   * Default request interceptor for Axios library
   * @context {VueAuthenticate}
   */
  VueAuthenticate.prototype.defaultBindRequestInterceptor = function defaultBindRequestInterceptor ($auth) {
    var tokenHeader = $auth.options.tokenHeader;

    $auth.$http.interceptors.request.use(function (request) {
      if ($auth.isAuthenticated()) {
        request.headers[tokenHeader] = [
          $auth.options.tokenType,
          $auth.getToken() ].join(' ');
      } else {
        delete request.headers[tokenHeader];
      }
      return request;
    });
  };

  VueAuthenticate.prototype.runAuthInterceptor = function runAuthInterceptor (error) {
    var chain = [];
    var promise = Promise$1.reject(error);

    this.options.refreshAuthFailInterceptors.forEach(function (interceptor){
      chain.unshift(interceptor);
    });

    while (chain.length) {
      promise = promise.catch(chain.shift());
    }

    return promise;
  };

  VueAuthenticate.prototype.defaultBindResponseInterceptor = function defaultBindResponseInterceptor ($auth) {
    $auth.$http.interceptors.response.use(function (response) {
      return response
    }, function (error) {
      var config = error.config;
        var status = error.response.status;
      var originalRequest = config;

      // Check if we should refresh the token
      // 1. unauthorized
      // 2. refreshType is set
      // 3. any token is set
      // if (status === 401 && $auth.options.refreshType && $auth.isTokenSet()) {
      if (status === 401 && $auth.options.refreshType) {
        console.log("Got 401 with refresh type");
        if($auth.isTokenSet()){
          console.log("Token was set");
          // check if we are already refreshing, to prevent endless loop
          if (!$auth._isRefreshing) {
            if($auth.last_token_refresh_attempt &&
              ((new Date) - $auth.last_token_refresh_attempt) < 5*60*100){ //check we haven't tried to refresh in the last 5 minutes
              // Don't retry a refresh on fail
              return $auth.runAuthInterceptor(error);
            }
            $auth._isRefreshing = true;
            $auth.last_token_refresh_attempt = new Date();
            // Try to refresh our token
            try {
              return $auth.refresh()
                .then(function (response) {
                  // refreshing was successful :)
                  $auth._isRefreshing = false;
                  // send original request
                  return $auth.$http(originalRequest)
                })
                .catch(function (error) {
                  // Refreshing fails :(
                  $auth._isRefreshing = false;
                  // return Promise.reject(error)
                  return $auth.runAuthInterceptor(error)
                })
            }catch (e){
              console.log("Shouldn't be here!");
              console.log(e);
              $auth._isRefreshing = false;
              // return Promise.reject(error)
              return $auth.runAuthInterceptor(error)

            }
          }else {
            // If refresh is already going, our request will run after it, e.g. when refreshed
            return new Promise$1(function (resolve, reject) {
              setTimeout(function (){
                $auth.$http(originalRequest).then(resolve).catch(reject);
              }, 100);
            });
          }
        }else {
          console.log("Token was not set");
          return $auth.runAuthInterceptor(error)
        }
      }
      console.log("fell through");
      return Promise$1.reject(error)
    });
  };

  /**
   * VueAuthenticate plugin
   * @param {Object} Vue
   * @param {Object} options
   */
  function plugin(Vue, options) {
    if (plugin.installed) {
      return;
    }

    plugin.installed = true;

    var vueAuthInstance = null;
    Object.defineProperties(Vue.prototype, {
      $auth: {
        get: function get() {
          if (!vueAuthInstance) {
            // Request handler library not found, throw error
            if (!this.$http) {
              throw new Error('Request handler instance not found');
            }

            vueAuthInstance = new VueAuthenticate(this.$http, options);
          }
          return vueAuthInstance;
        },
      },
    });
  }

  /**
   * External factory helper for ES5 and CommonJS
   * @param  {Object} $http     Instance of request handling library
   * @param  {Object} options   Configuration object
   * @return {VueAuthenticate}  VueAuthenticate instance
   */
  plugin.factory = function ($http, options) {
    return new VueAuthenticate($http, options);
  };

  return plugin;

})));
