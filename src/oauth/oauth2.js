import OAuthPopup from './popup.js';
import {
  camelCase,
  isFunction,
  isString,
  objectExtend,
  joinUrl, makeRequestOptions,
} from '../utils.js';

import sha256 from 'crypto-js/sha256';
import Base64 from 'crypto-js/enc-base64';
import WordArray from 'crypto-js/lib-typedarrays';
import Promise from "../promise";

/**
 * Default provider configuration
 * @type {Object}
 */
const defaultProviderConfig = {
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
  tokenRequestAsForm: false,
  refreshRequestAsForm: false,
  refreshGrantType: null,
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

export default class OAuth2 {
  constructor($http, storage, providerConfig, options) {
    this.$http = $http;
    this.storage = storage;
    this.providerConfig = objectExtend({}, defaultProviderConfig);
    this.providerConfig = objectExtend(this.providerConfig, providerConfig);
    this.options = options;
  }

  getRandomString(key) {
    if(!this.storage.getItem(key)) {
      this.storage.setItem(key, WordArray.random(64));
    }

    console.log(this.storage.getItem(key));
    return this.storage.getItem(key);
  }

  init(userData) {
    let stateName = this.providerConfig.name + '_state';
    if (isFunction(this.providerConfig.state)) {
      this.storage.setItem(stateName, this.providerConfig.state());
    } else if (isString(this.providerConfig.state)) {
      this.storage.setItem(stateName, this.providerConfig.state);
    }

    let url = [
      this.providerConfig.authorizationEndpoint,
      this._stringifyRequestParams(),
    ].join('?');


    if(this.providerConfig.pkce === 'S256'){
      if(this.providerConfig.responseType !== 'code'){
        throw new Error(`Cannot use PKCE with response type ${this.providerConfig.responseType}`);
      }
      const hashed = sha256(this.getRandomString(this.providerConfig.name + '_pkce'));
      var pkce_challenge = Base64.stringify(hashed).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

      url = `${url}&code_challenge=${encodeURIComponent(pkce_challenge)}&code_challenge_method=S256`
    }

    this.oauthPopup = new OAuthPopup(
      url,
      this.providerConfig.name,
      this.providerConfig.popupOptions
    );

    return new Promise((resolve, reject) => {
      this.oauthPopup
        .open(this.providerConfig.redirectUri)
        .then(response => {
          if (
            this.providerConfig.responseType === 'token' ||
            !this.providerConfig.url
          ) {
            return resolve(response);
          }

          if (
            response.state &&
            response.state !== this.storage.getItem(stateName)
          ) {
            return reject(
              new Error(
                'State parameter value does not match original OAuth request state value'
              )
            );
          }

          this.exchangeForToken(response, userData).then((response)=>{
            this.storage.removeItem(this.providerConfig.name + '_pkce');
            return response.data;
          }).then(resolve);
        })
        .catch(err => {
          reject(err);
        });
    });
  }

  /**
   * Exchange temporary oauth data for access token
   * @author Sahat Yalkabov <https://github.com/sahat>
   * @copyright Method taken from https://github.com/sahat/satellizer
   *
   * @param  {[type]} oauth    [description]
   * @param  {[type]} userData [description]
   * @return {[type]}          [description]
   */
  exchangeForToken(oauth, userData) {
    let payload = objectExtend({}, userData);

    for (let key in this.providerConfig.responseParams) {
      let value = this.providerConfig.responseParams[key];

      switch (key) {
        case 'code':
          payload[value] = oauth.code
          break
        case 'clientId':
          payload[value] = this.providerConfig.clientId
          break
        case 'redirectUri':
          payload[value] = this.providerConfig.redirectUri
          break
        default:
          payload[value] = oauth[key]
      }
    }

    if (oauth.state) {
      payload.state = oauth.state;
    }

    let exchangeTokenUrl;
    if (this.options.baseUrl) {
      exchangeTokenUrl = joinUrl(this.options.baseUrl, this.providerConfig.url);
    } else {
      exchangeTokenUrl = this.providerConfig.url;
    }

    let pkceVerifier = this.getRandomString(this.providerConfig.name + '_pkce');
    if(pkceVerifier){
      payload['code_verifier'] = pkceVerifier;
      payload['grant_type'] = 'authorization_code';
      console.log(pkceVerifier);
    }

    if(this.providerConfig.tokenRequestAsForm){
      var form = new FormData();
      for (let key in payload) {
        let value = payload[key];
        form.append(key, value);
      }
      payload = form;
    }

    return this.$http.post(exchangeTokenUrl, payload, {
      withCredentials: this.options.withCredentials,
    });
  }

  /**
   * Stringify oauth params
   * @author Sahat Yalkabov <https://github.com/sahat>
   * @copyright Method taken from https://github.com/sahat/satellizer
   *
   * @return {String}
   */
  _stringifyRequestParams() {
    let keyValuePairs = [];
    let paramCategories = [
      'defaultUrlParams',
      'requiredUrlParams',
      'optionalUrlParams',
    ];

    paramCategories.forEach(categoryName => {
      if (!this.providerConfig[categoryName]) return;
      if (!Array.isArray(this.providerConfig[categoryName])) return;

      this.providerConfig[categoryName].forEach(paramName => {
        let camelCaseParamName = camelCase(paramName);
        let paramValue = isFunction(this.providerConfig[paramName])
          ? this.providerConfig[paramName]()
          : this.providerConfig[camelCaseParamName];

        if (paramName === 'redirect_uri' && !paramValue) return;

        if (paramName === 'state') {
          let stateName = this.providerConfig.name + '_state';
          paramValue = encodeURIComponent(this.storage.getItem(stateName));
        }
        if (paramName === 'scope' && Array.isArray(paramValue)) {
          paramValue = paramValue.join(this.providerConfig.scopeDelimiter);
          if (this.providerConfig.scopePrefix) {
            paramValue = [this.providerConfig.scopePrefix, paramValue].join(
              this.providerConfig.scopeDelimiter
            );
          }
        }

        keyValuePairs.push([paramName, paramValue]);
      });
    });

    return keyValuePairs
      .map(param => {
        return param.join('=');
      })
      .join('&');
  }

  /**
   * Get refresh token
   * @returns {String|null} refresh token
   */
  getRefreshToken(name) {
    if (this.options.refreshType === 'storage')
      return this.storage.getItem(name)

    return null;
  }

  /**
   * Refresh access token
   * @param requestOptions  Request options
   * @returns {Promise}     Request Promise
   */
  refresh(refreshTokenName) {
    if (!this.options.storageType) {
      throw new Error('Refreshing is not set');
    }

    let data = {};

    if (this.options.refreshType === 'storage')
      data.refresh_token = this.getRefreshToken(refreshTokenName);

    for (let key in this.providerConfig.refreshParams) {
      let value = this.providerConfig.refreshParams[key];

      switch (key) {
        case 'clientId':
          data[value] = this.providerConfig.clientId
          break
        case 'grantType':
          data[value] = this.providerConfig.refreshGrantType
          break
        default:
          data[value] = this.providerConfig[key]
      }
    }

    if (this.providerConfig.refreshRequestAsForm) {
      var form = new FormData();
      for (let key in data) {
        let value = data[key];

        form.set(key, value);
      }

      data = form;
    }

    var requestOptions = makeRequestOptions(this.providerConfig, this.options, 'refreshUrl', data);
    return this.$http(requestOptions);
  }
}
