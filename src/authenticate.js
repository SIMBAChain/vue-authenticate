import Promise from './promise.js'
import { $window } from './globals.js';
import {
  objectExtend,
  isString,
  isObject,
  isFunction,
  joinUrl,
  decodeBase64,
  getObjectProperty,
  makeRequestOptions,
  isUndefined,
  parseJWT
} from './utils.js'
import defaultOptions from './options.js'
import StorageFactory from './storage.js'
import OAuth1 from './oauth/oauth1.js'
import OAuth2 from './oauth/oauth2.js'

export default class VueAuthenticate {
  constructor($http, overrideOptions) {
    let options = objectExtend({}, defaultOptions);
    options = objectExtend(options, overrideOptions);
    let storage = StorageFactory(options);

    Object.defineProperties(this, {
      $http: {
        get() {
          return $http;
        },
      },

      options: {
        get() {
          return options;
        },
      },

      storage: {
        get() {
          return storage;
        },
      },

      tokenName: {
        get() {
          if (this.options.tokenPrefix) {
            return [this.options.tokenPrefix, this.options.tokenName].join('_');
          } else {
            return this.options.tokenName;
          }
        }
      },

      refreshTokenName: {
        get() {
          if (this.options.refreshTokenPrefix) {
            return [this.options.refreshTokenPrefix, this.options.refreshTokenName].join('_')
          } else {
            return this.options.refreshTokenName
          }
        }
      },

      expirationName: {
        get() {
          if (this.options.expirationPrefix) {
            return [this.options.expirationPrefix, this.options.expirationName].join('_')
          } else {
            return this.options.expirationName
          }
        }
      }
    })

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
        this.options.bindResponseInterceptor.call(this, this)
      }else {
        throw new Error('Response interceptor must be functions')
      }
    } else {
      this.defaultBindResponseInterceptor(this, this);
    }
  }

  /**
   * Check if user is authenticated
   * @author Sahat Yalkabov <https://github.com/sahat>
   * @copyright Method taken from https://github.com/sahat/satellizer
   * @return {Boolean}
   */
  isAuthenticated() {
    let token = this.storage.getItem(this.tokenName);

    if (token) {
      // Token is present
      if (token.split('.').length === 3) {
        // Token with a valid JWT format XXX.YYY.ZZZ
        try {
          // Could be a valid JWT or an access token with the same format
          const exp = parseJWT(token).exp;
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
  }

  /**
   * Returns if a token is set
   * @returns {boolean}
   */
  isTokenSet() {
    if (isUndefined(this.getToken())) return false;
    return !!this.getToken()
  }

  /**
   * Get token if user is authenticated
   * @return {String} Authentication token
   */
  getToken() {
    return this.storage.getItem(this.tokenName);
  }

  /**
   * Set new authentication token
   * @param {String|Object} response
   */
  setToken(response, tokenPath) {
    if (response[this.options.responseDataKey]) {
      response = response[this.options.responseDataKey];
    }

    const responseTokenPath = tokenPath || this.options.tokenPath;
    const token = getObjectProperty(response, responseTokenPath);

    if (token) {
      this.storage.setItem(this.tokenName, token);
    }
  }

  /**
   * Get the logged in provider
   * @return {String} provider
   */
  getLoggedInProvider() {
    return this.storage.getItem('LoggedInProvider');
  }

  /**
   * Set logged in provider
   * @param {String} provider
   */
  setLoggedInProvider(provider) {
      this.storage.setItem('LoggedInProvider', provider);
  }

  /**
   * Get expiration of the access token
   * @returns {number|null} expiration
   */
  getExpiration() {
    if (this.options.refreshType)
      return this.storage.getItem(this.expirationName)
    return null;
  }

  /**
   * Set new refresh token
   * @param {String|Object} response
   * @param {String} tokenPath
   * @returns {String|Object} response
   */
  setRefreshToken(response, tokenPath) {
    // Check if refresh token is required
    if (!this.options.refreshType) {
      return;
    }

    if (response[this.options.responseDataKey]) {
      response = response[this.options.responseDataKey];
    }

    this.setExpiration(response)
    // set refresh token if it's not provided over a HttpOnly cookie
    if (!(this.options.refreshType === 'storage')) {
      return response;
    }

    const refreshTokenPath = tokenPath || this.options.refreshTokenPath;
    let refresh_token = getObjectProperty(response, refreshTokenPath);

    if (!refresh_token && response) {
      refresh_token = response[this.options.expirationName]
    }

    if (refresh_token) {
      this.storage.setItem(this.refreshTokenName, refresh_token)
    }

    return response
  }

  /**
   * Sets the expiration of the access token
   * @param {String|Object} response
   * @returns {String|Object} response
   */
  setExpiration(response) {
    // set expiration of access token
    let expiration;
    if (response.expires_in) {
      let expires_in = parseInt(response.expires_in)
      if (isNaN(expires_in)) expires_in = 0
      expiration = Math.round(new Date().getTime() / 1000) + expires_in
    }

    if (!expiration && response) {
      let expires_in = parseInt(response[this.options.expirationName])
      if (isNaN(expires_in)) expires_in = 0
      expiration = Math.round(new Date().getTime() / 1000) + expires_in
    }

    if (expiration) {
      this.storage.setItem(this.expirationName, expiration)
    }

    return response
  }


  getPayload() {
    const token = this.storage.getItem(this.tokenName);

    if (token && token.split('.').length === 3) {
      try {
        const base64Url = token.split('.')[1];
        const base64 = base64Url.replace('-', '+').replace('_', '/');
        return JSON.parse(decodeBase64(base64));
      } catch (e) {
      }
    }
  }

  /**
   * Login user using email and password
   * @param  {Object} user           User data
   * @param  {Object} requestOptions Request options
   * @return {Promise}               Request promise
   */
  login(user, requestOptions) {
    requestOptions = makeRequestOptions(requestOptions, this.options, 'loginUrl', user);

    return this.$http(requestOptions)
      .then(response => {
        this.setToken(response)
        this.setRefreshToken(response)
        // Check if we are authenticated
        if(this.isAuthenticated()){
          return Promise.resolve(response);
        }
        throw new Error('Server did not provided an access token.');
      })
      .catch(error => {
        return Promise.reject(error)
      })
  }

  /**
   * Register new user
   * @param  {Object} user           User data
   * @param  {Object} requestOptions Request options
   * @return {Promise}               Request promise
   */
  register(user, requestOptions) {
    requestOptions = makeRequestOptions(requestOptions, this.options, 'registerUrl', user)

    return this.$http(requestOptions)
      .then((response) => {
        this.setToken(response);
        this.setRefreshToken(response);
        return Promise.resolve(response);
      })
      .catch(err => Promise.reject(err))
  }

  /**
   * Logout current user
   * @param  {Object} requestOptions  Logout request options object
   * @return {Promise}                Request promise
   */
  logout(requestOptions) {
    if (!this.isAuthenticated()) {
      return Promise.reject(
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
        .then((response) => {
          this.storage.removeItem(this.tokenName);
          return Promise.resolve(response);
        })
        .catch(err => Promise.reject(err))
    } else {
      this.storage.removeItem(this.tokenName);
      return Promise.resolve();
    }
  }

  /**
   * Refresh access token
   * @param requestOptions  Request options
   * @returns {Promise}     Request Promise
   */
  refresh() {
    const provider = this.getLoggedInProvider();
    const providerConfig = this.options.providers[provider];
    const refreshTokenName = this.refreshTokenName;

    if (!providerConfig) {
      return reject(new Error('Unknown provider'));
    }

    let providerInstance;
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
      .then((response) => {
        this.setToken(response);
        this.setRefreshToken(response);
        return response;
      })
      .catch((error) => {
        this.clearStorage();
        throw error;
      })
  }

  /**
   * Remove all item from the storage
   */
  clearStorage() {
    this.storage.removeItem(this.tokenName)
    this.storage.removeItem(this.expirationName)
    this.storage.removeItem(this.refreshTokenName)
  }

  /**
   * Authenticate user using authentication provider
   *
   * @param  {String} provider       Provider name
   * @param  {Object} userData       User data
   * @return {Promise}               Request promise
   */
  authenticate(provider, userData) {
    return new Promise((resolve, reject) => {
      var providerConfig = this.options.providers[provider];
      if (!providerConfig) {
        return reject(new Error('Unknown provider'));
      }

      let providerInstance;
      switch (providerConfig.oauthType) {
        case '1.0':
          providerInstance = new OAuth1(
            this.$http,
            this.storage,
            providerConfig,
            this.options
          );
          break;
        case '2.0':
          providerInstance = new OAuth2(
            this.$http,
            this.storage,
            providerConfig,
            this.options
          );
          break;
        default:
          return reject(new Error('Invalid OAuth type'));
      }

      return providerInstance
        .init(userData)
        .then(response => {
          this.setToken(response, providerConfig.tokenPath);
          this.setRefreshToken(response, providerConfig.refreshTokenPath)
          this.setLoggedInProvider(provider);

          if (this.isAuthenticated()) {
            return resolve(response);
          } else {
            return reject(new Error('Authentication failed'));
          }
        })
        .catch(err => reject(err));
    });
  }

  /**
   * Link user using authentication provider without login
   *
   * @param  {String} provider       Provider name
   * @param  {Object} userData       User data
   * @return {Promise}               Request promise
   */
  link(provider, userData) {
    return new Promise((resolve, reject) => {
      var providerConfig = this.options.providers[provider];
      if (!providerConfig) {
        return reject(new Error('Unknown provider'));
      }

      let providerInstance;
      switch (providerConfig.oauthType) {
        case '1.0':
          providerInstance = new OAuth1(
            this.$http,
            this.storage,
            providerConfig,
            this.options
          );
          break;
        case '2.0':
          providerInstance = new OAuth2(
            this.$http,
            this.storage,
            providerConfig,
            this.options
          );
          break;
        default:
          return reject(new Error('Invalid OAuth type'));
      }

      return providerInstance
        .init(userData)
        .then(response => {
          if (response[this.options.responseDataKey]) {
            response = response[this.options.responseDataKey];
          }

          resolve(response);
        })
        .catch(reject);
    });
  }

  /**
   * Default request interceptor for Axios library
   * @context {VueAuthenticate}
   */
  defaultBindRequestInterceptor($auth) {
    const tokenHeader = $auth.options.tokenHeader;

    $auth.$http.interceptors.request.use((request) => {
      if ($auth.isAuthenticated()) {
        request.headers[tokenHeader] = [
          $auth.options.tokenType,
          $auth.getToken(),
        ].join(' ');
      } else {
        delete request.headers[tokenHeader];
      }
      return request;
    });
  }

  runAuthInterceptor(error) {
    var chain = [];
    var promise = Promise.reject(error);

    this.options.refreshAuthFailInterceptors.forEach((interceptor)=>{
      chain.unshift(interceptor);
    })

    while (chain.length) {
      promise = promise.catch(chain.shift());
    }

    return promise;
  }

  defaultBindResponseInterceptor($auth) {
    $auth.$http.interceptors.response.use((response) => {
      return response
    }, (error) => {
      const {config, response: {status}} = error
      const originalRequest = config

      // Check if we should refresh the token
      // 1. unauthorized
      // 2. refreshType is set
      // 3. any token is set
      // if (status === 401 && $auth.options.refreshType && $auth.isTokenSet()) {
      if (status === 401 && $auth.options.refreshType) {
        console.log("Got 401 with refresh type")
        if($auth.isTokenSet()){
          console.log("Token was set")
          // check if we are already refreshing, to prevent endless loop
          if (!$auth._isRefreshing) {
            if($auth.last_token_refresh_attempt &&
              ((new Date) - $auth.last_token_refresh_attempt) < 5*60*100){ //check we haven't tried to refresh in the last 5 minutes
              // Don't retry a refresh on fail
              return $auth.runAuthInterceptor(error);
            }
            $auth._isRefreshing = true
            $auth.last_token_refresh_attempt = new Date();
            // Try to refresh our token
            try {
              return $auth.refresh()
                .then(response => {
                  // refreshing was successful :)
                  $auth._isRefreshing = false
                  // send original request
                  return $auth.$http(originalRequest)
                })
                .catch(error => {
                  // Refreshing fails :(
                  $auth._isRefreshing = false
                  // return Promise.reject(error)
                  return $auth.runAuthInterceptor(error)
                })
            }catch (e){
              console.log("Shouldn't be here!");
              console.log(e);
              $auth._isRefreshing = false
              // return Promise.reject(error)
              return $auth.runAuthInterceptor(error)

            }
          }else{
            // If refresh is already going, our request will run after it, e.g. when refreshed
            return new Promise((resolve, reject) =>{
              setTimeout(()=>{
                $auth.$http(originalRequest).then(resolve).catch(reject);
              }, 100);
            });
          }
        }else {
          console.log("Token was not set")
          return $auth.runAuthInterceptor(error)
        }
      }
      console.log("fell through")
      return Promise.reject(error)
    });
  }

}
