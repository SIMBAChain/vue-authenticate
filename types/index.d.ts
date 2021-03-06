import {
  VueConstructor
} from "vue";
import { AxiosResponse, AxiosRequestConfig } from "axios";

export default function plugin(Vue: VueConstructor, options?: any): void;

export interface CookieStorageOptions {
  domain?: string;
  path?: string;
  secure?: boolean;
}

export interface ProviderOptions {
  name?: string;
  url?: string;
  clientId?: string;
  authorizationEndpoint?: string;
  redirectUri?: string;
  requiredUrlParams?: string[];
  defaultUrlParams?: string[];
  optionalUrlParams?: string[];
  scope?: string[];
  scopePrefix?: string;
  scopeDelimiter?: string;
  state?: string;
  display?: string;
  oauthType?: string;
  responseType?: string;
  responseParams?: {
    code?: string;
    clientId?: string;
    redirectUri?: string;
  };
  tokenRequestAsForm: boolean,
  refreshRequestAsForm: boolean,
  refreshGrantType?: string,
  pkce: boolean,
  refreshParams?: {
    clientId?: string;
    grantType?: string;
    scope?: string;
  };
  popupOptions?: {
    width: number;
    height: number;
  };
}
export declare class VueAuthenticate {
  login(user: Object): Promise<AxiosResponse>;
  login(
    user: Object,
    requestOptions: AxiosRequestConfig
  ): Promise<AxiosResponse>;
  isAuthenticated(): boolean;
  getToken(): string;
  getLoggedInProvider(): string;
  setToken(token: string | object): void;
  setLoggedInProvider(provider: string | object): void;
  setRefreshToken(response: string|object, tokenPath: string|null): string|object;
  setExpiration(response: string|object): string|object;
  register(
    user: any,
    requestOptions?: AxiosRequestConfig
  ): Promise<AxiosResponse>;
  logout(requestOptions?: AxiosRequestConfig): Promise<AxiosResponse>;
  refresh(): Promise<AxiosResponse>;
  authenticate(
    provider: string,
    userData: any,
    requestOptions?: AxiosRequestConfig
  ): Promise<{}>;
}
export interface AuthenticateOptions {
  baseUrl?: string;
  tokenName?: string;
  tokenPrefix?: string;
  tokenHeader?: string;
  tokenType?: string;
  loginUrl?: string;
  registerUrl?: string;
  logoutUrl?: string;
  storageType?: string;
  storageNamespace?: string;
  cookieStorage?: CookieStorageOptions;
  requestDataKey?: string;
  responseDataKey?: string;
  withCredentials?: boolean;
  providers: { [key: string]: ProviderOptions };
  refreshType?: string,
  refreshTokenName?: string,
  refreshTokenPrefix?: string,
  pkce: boolean,
  refreshAuthFailInterceptors: Promise<any>[]
}

declare module "vue/types/vue" {
  interface Vue {
    $auth: VueAuthenticate;
  }
}
