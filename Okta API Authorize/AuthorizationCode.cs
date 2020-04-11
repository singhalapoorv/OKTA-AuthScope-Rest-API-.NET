
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;

namespace IAM.GrantTypeFlow
{
    public class AuthorizationCode : IPKCE, IAuthorizationCode
    {
        # region Properties and Constructor

        public String AuthServer { get; set; }
        public AuthorizationCode(String AuthorizationServer)
        {
            AuthServer = AuthorizationServer;
        }

        # endregion Properties and Constructor

        # region Grant_Methods

        public OktaTokenDTO Authorization_Code_PKCE_Flow(OktaTokenDTO BaseToken)
        {
            try
            {
                CookieCollection cookies = new CookieCollection();
                HttpHelper.apiBaseUri = AuthServer;
                HttpHelper.AllowAutoRedirect = false;
                var authorizeUri = AuthServer + "/v1/authorize?client_id=" + Settings.client_Id + "&redirect_uri=" + Settings.redirectUrlEncoded
                    + "&response_type=" + Settings.responseType + "&sessionToken=" + BaseToken.SessionToken.Value + "&state=" + TKSCryptography.RandomGenerateBinaryToHex() + "&nonce=" + TKSCryptography.RandomGenerateBinaryToHex()
                    + "&scope=" + Settings.default_auth_scope + "&code_challenge_method=" + Settings.code_challenge_method + "&code_challenge=" + Settings.code_challenge;
                HttpResponseMessage authorizeResponse = HttpHelper.Get(authorizeUri, out cookies);
                var statusCode = authorizeResponse.StatusCode;
                if (statusCode == System.Net.HttpStatusCode.Found)
                {
                    BaseToken.Cookies = cookies;
                    var redirectUri = authorizeResponse.Headers.Location;
                    var queryAuthDictionary = HttpUtility.ParseQueryString(redirectUri.AbsoluteUri);
                    var codeKey = Settings.redirectUrl + "?code";
                    var code = queryAuthDictionary[codeKey];
                    var body = new Dictionary<string, string>    
                                {    
                                    {"grant_type", "authorization_code"},
                                    {"redirect_uri", Settings.redirectUrl},
                                    {"client_id", Settings.client_Id},                                
                                    {"code", code},
                                    {"code_verifier", Settings.code_verifier},                                     
                                };
                    IEnumerable<KeyValuePair<string, string>> kvp = body.Select((pair) => pair);
                    var _tokenUri = AuthServer + "/v1/token";
                    HttpHelper.apiBaseUri = AuthServer;
                    var tokenResponse = HttpHelper.PostFormUrlEncoded(_tokenUri, kvp);
                    if (tokenResponse.StatusCode == System.Net.HttpStatusCode.OK)
                    {
                        var tokenResult = tokenResponse.Content.ReadAsStringAsync().Result;
                        var tokenObj = JSONHelper.Parse(tokenResult.ToString());
                        if (tokenObj["access_token"] != null)
                        {
                            BaseToken.AccessToken.Value = Convert.ToString(tokenObj["access_token"]);
                            if (tokenObj["expires_in"] != null)
                                BaseToken.AccessToken.Expires_In = Convert.ToInt32(tokenObj["expires_in"]);
                        }
                        if (tokenObj["token_type"] != null)
                            BaseToken.TokenType = Convert.ToString(tokenObj["token_type"]);
                        if (tokenObj["scope"] != null)
                            BaseToken.Scope = Convert.ToString(tokenObj["scope"]);
                        if (tokenObj["id_token"] != null)
                        {
                            BaseToken.IDToken.Value = Convert.ToString(tokenObj["id_token"]);
                            if (tokenObj["expires_in"] != null)
                                BaseToken.IDToken.Expires_In = Convert.ToInt32(tokenObj["expires_in"]);
                        }
                        if (tokenObj["refresh_token"] != null)
                        {
                            BaseToken.RefreshToken.Value = Convert.ToString(tokenObj["refresh_token"]);
                            if (tokenObj["expires_in"] != null)
                                BaseToken.RefreshToken.Expires_In = Convert.ToInt32(tokenObj["expires_in"]);
                        }
                    }
                    else
                        BaseToken.Grant_Error = tokenResponse.Content.ReadAsStringAsync().Result;
                }
                else
                    BaseToken.Grant_Error = authorizeResponse.Content.ReadAsStringAsync().Result;

                return BaseToken;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        public OktaTokenDTO Authorization_Code_Flow(OktaTokenDTO BaseToken)
        {
            try
            {
                CookieCollection cookies = new CookieCollection();
                HttpHelper.apiBaseUri = AuthServer;
                HttpHelper.AllowAutoRedirect = false;
                var authorizeUri = AuthServer + "/v1/authorize?client_id=" + Settings.client_Id + "&redirect_uri=" + Settings.redirectUrlEncoded
                    + "&response_type=" + Settings.responseType + "&scope=" + Settings.default_auth_scope + "&sessionToken=" + BaseToken.SessionToken.Value + "&state=" + TKSCryptography.RandomGenerateBinaryToHex();
                HttpResponseMessage authorizeResponse = HttpHelper.Get(authorizeUri, out cookies);
                var statusCode = authorizeResponse.StatusCode;
                if (statusCode == System.Net.HttpStatusCode.Found)
                {
                    var redirectUri = authorizeResponse.Headers.Location;
                    BaseToken.Cookies = cookies;
                    var queryAuthDictionary = HttpUtility.ParseQueryString(redirectUri.AbsoluteUri);
                    String error = ValidateGrantError(queryAuthDictionary);
                    if (!String.IsNullOrEmpty(error))
                        BaseToken.Grant_Error = error;
                    else
                    {
                        var codeKey = Settings.redirectUrl + "?code";
                        var code = queryAuthDictionary[codeKey];
                        var body = new Dictionary<string, string>    
                                {    
                                    {"code", code},
                                    {"grant_type", "authorization_code"},
                                    {"client_id", Settings.client_Id},
                                    {"client_secret", Settings.client_secret}, 
                                    {"redirect_uri", Settings.redirectUrl},                                  
                                };
                        IEnumerable<KeyValuePair<string, string>> kvp = body.Select((pair) => pair);
                        var _tokenUri = AuthServer + "/v1/token";
                        HttpHelper.apiBaseUri = AuthServer;
                        var tokenResponse = HttpHelper.PostFormUrlEncoded(_tokenUri, kvp);
                        if (tokenResponse.StatusCode == System.Net.HttpStatusCode.OK)
                        {
                            var tokenResult = tokenResponse.Content.ReadAsStringAsync().Result;
                            var tokenObj = JSONHelper.Parse(tokenResult.ToString());
                            if (tokenObj["access_token"] != null)
                            {
                                BaseToken.AccessToken.Value = Convert.ToString(tokenObj["access_token"]);
                                if (tokenObj["expires_in"] != null)
                                    BaseToken.AccessToken.Expires_In = Convert.ToInt32(tokenObj["expires_in"]);
                            }
                            if (tokenObj["token_type"] != null)
                                BaseToken.TokenType = Convert.ToString(tokenObj["token_type"]);
                            if (tokenObj["scope"] != null)
                                BaseToken.Scope = Convert.ToString(tokenObj["scope"]);
                            if (tokenObj["id_token"] != null)
                            {
                                BaseToken.IDToken.Value = Convert.ToString(tokenObj["id_token"]);
                                if (tokenObj["expires_in"] != null)
                                    BaseToken.IDToken.Expires_In = Convert.ToInt32(tokenObj["expires_in"]);
                            }
                            if (tokenObj["refresh_token"] != null)
                            {
                                BaseToken.RefreshToken.Value = Convert.ToString(tokenObj["refresh_token"]);
                                if (tokenObj["expires_in"] != null)
                                    BaseToken.RefreshToken.Expires_In = Convert.ToInt32(tokenObj["expires_in"]);
                            }
                        }
                        else
                            BaseToken.Grant_Error = tokenResponse.Content.ReadAsStringAsync().Result;
                    }
                }
                else
                    BaseToken.Grant_Error = authorizeResponse.Content.ReadAsStringAsync().Result;

                return BaseToken;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

public static String RandomGenerateBinaryToHex()
        {
            var csprng = new RNGCryptoServiceProvider();
            var bytes = new byte[8];
            csprng.GetNonZeroBytes(bytes);
            return string.Join("", bytes.Select(b => b.ToString("x2"))); // or "X2" for upper case
        }
	
	public static HttpResponseMessage PostFormUrlEncoded(string url, IEnumerable<KeyValuePair<string, string>> postData)
        {
            using (var httpClient = new HttpClient())
            {
                httpClient.DefaultRequestHeaders
                            .Accept
                            .Add(new MediaTypeWithQualityHeaderValue("application/json"));
                using (var content = new FormUrlEncodedContent(postData))
                {
                    content.Headers.Clear();
                    content.Headers.Add("Content-Type", "application/x-www-form-urlencoded");
                    var response = httpClient.PostAsync(url, content).GetAwaiter().GetResult();
                    return response;
                }
            }
        }
		
        public OktaTokenDTO Default_Authorization_Server_Code_Flow(OktaTokenDTO BaseToken)
        {
            try
            {
                CookieCollection cookies = new CookieCollection();
                HttpHelper.apiBaseUri = AuthServer;
                HttpHelper.AllowAutoRedirect = false;
                var authorizeUri = AuthServer + "/v1/authorize?client_id=" + #OKTA client_Id# + "&redirect_uri=" + #OKTA redirect URL#
                    + "&response_type=" + #OKTA responseType (code)# + "&scope=" + #OKTA default auth scope (openid)# + "&sessionToken=" + BaseToken.SessionToken.Value + "&state=" + RandomGenerateBinaryToHex();
                HttpResponseMessage authorizeResponse = HttpHelper.Get(authorizeUri, out cookies);
                var statusCode = authorizeResponse.StatusCode;
                if (statusCode == System.Net.HttpStatusCode.Found)
                {
                    var redirectUri = authorizeResponse.Headers.Location;
                    BaseToken.Cookies = cookies;
                    var queryAuthDictionary = HttpUtility.ParseQueryString(redirectUri.AbsoluteUri);
                    String error = ValidateGrantError(queryAuthDictionary);
                    if (!String.IsNullOrEmpty(error))
                        BaseToken.Grant_Error = error;
                    else
                    {
                        var codeKey = Settings.redirectUrl + "?code";
                        var code = queryAuthDictionary[codeKey];
                        var body = new Dictionary<string, string>    
                                {    
                                    {"code", code},
                                    {"grant_type", "authorization_code"},
                                    {"client_id", OKTA client_Id},
                                    {"client_secret", OKTA client_secret}, 
                                    {"redirect_uri", OKTA redirectUrl},                                  
                                };
                        IEnumerable<KeyValuePair<string, string>> kvp = body.Select((pair) => pair);
                        var _tokenUri = AuthServer + "/v1/token";
                        HttpHelper.apiBaseUri = AuthServer;
                        var tokenResponse = HttpHelper.PostFormUrlEncoded(_tokenUri, kvp);
                        if (tokenResponse.StatusCode == System.Net.HttpStatusCode.OK)
                        {
                            var tokenResult = tokenResponse.Content.ReadAsStringAsync().Result;
                            var tokenObj = JSONHelper.Parse(tokenResult.ToString());
                            if (tokenObj["access_token"] != null)
                            {
                                BaseToken.AccessToken.Value = Convert.ToString(tokenObj["access_token"]);
                                if (tokenObj["expires_in"] != null)
                                    BaseToken.AccessToken.Expires_In = Convert.ToInt32(tokenObj["expires_in"]);
                            }
                        }
                        else
                            BaseToken.Grant_Error = tokenResponse.Content.ReadAsStringAsync().Result;
                    }
                }
                else
                    BaseToken.Grant_Error = authorizeResponse.Content.ReadAsStringAsync().Result;

                return BaseToken;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        /// <summary>
        /// Returns accesstoken with BaseToken.AuthenticationStatus can be "SUCCESS" or "FAILED"
        /// </summary>
        /// <param name="BaseToken"></param>
        /// <param name="CustomScope"></param>
        /// <returns></returns>
        public OktaTokenDTO Custom_Authorization_Server_Code_Flow(OktaTokenDTO BaseToken, String CustomScope)
        {
            try
            {
                BaseToken.AuthenticationStatus = "FAILED";
                if (String.IsNullOrEmpty(CustomScope))
                    throw new ArgumentNullException("CustomScope required");
                HttpHelper.apiBaseUri = AuthServer;
                HttpHelper.AllowAutoRedirect = false;
                var authorizeUri = AuthServer + "/v1/authorize?client_id=" + Settings.client_Id + "&redirect_uri=" + Settings.redirectUrlEncoded
                    + "&response_type=" + Settings.responseType + "&scope=" + System.Net.WebUtility.UrlEncode(CustomScope) + "&state=" + TKSCryptography.RandomGenerateBinaryToHex();
                List<KeyValuePair<string, string>> requestCookies = new List<KeyValuePair<string, string>>();
                requestCookies.Add(new KeyValuePair<string, string>("sid", BaseToken.SessionId));
                HttpResponseMessage authorizeResponse = HttpHelper.Get(authorizeUri, requestCookies);
                var statusCode = authorizeResponse.StatusCode;
                if (statusCode == System.Net.HttpStatusCode.Found)
                {
                    var redirectUri = authorizeResponse.Headers.Location;
                    var queryAuthDictionary = HttpUtility.ParseQueryString(redirectUri.AbsoluteUri);
                    String error = ValidateGrantError(queryAuthDictionary);
                    if (!String.IsNullOrEmpty(error))
                        BaseToken.Grant_Error = error;
                    else
                    {
                        var codeKey = Settings.redirectUrl + "?code";
                        var code = queryAuthDictionary[codeKey];
                        var body = new Dictionary<string, string>    
                                {    
                                    {"code", code},
                                    {"grant_type", "authorization_code"},
                                    {"client_id", Settings.client_Id},
                                    {"client_secret", Settings.client_secret}, 
                                    {"redirect_uri", Settings.redirectUrl},                                  
                                };
                        IEnumerable<KeyValuePair<string, string>> kvp = body.Select((pair) => pair);
                        var _tokenUri = AuthServer + "/v1/token";
                        HttpHelper.apiBaseUri = AuthServer;
                        var tokenResponse = HttpHelper.PostFormUrlEncoded(_tokenUri, kvp);
                        if (tokenResponse.StatusCode == System.Net.HttpStatusCode.OK)
                        {
                            var tokenResult = tokenResponse.Content.ReadAsStringAsync().Result;
                            var tokenObj = JSONHelper.Parse(tokenResult.ToString());
                            BaseToken.AuthenticationStatus = "SUCCESS";
                            if (tokenObj["access_token"] != null)
                            {
                                BaseToken.AccessToken.Value = Convert.ToString(tokenObj["access_token"]);
                                if (tokenObj["expires_in"] != null)
                                    BaseToken.AccessToken.Expires_In = Convert.ToInt32(tokenObj["expires_in"]);
                            }
                            if (tokenObj["token_type"] != null)
                                BaseToken.TokenType = Convert.ToString(tokenObj["token_type"]);
                            if (tokenObj["scope"] != null)
                                BaseToken.Scope = Convert.ToString(tokenObj["scope"]);
                            if (tokenObj["refresh_token"] != null)
                            {
                                BaseToken.RefreshToken.Value = Convert.ToString(tokenObj["refresh_token"]);
                                if (tokenObj["expires_in"] != null)
                                    BaseToken.RefreshToken.Expires_In = Convert.ToInt32(tokenObj["expires_in"]);
                            }
                            //Identity moved to authentication handler
                            //SetCurrentUserIdentity(BaseToken.AccessToken);
                        }
                        else
                            BaseToken.Grant_Error = tokenResponse.Content.ReadAsStringAsync().Result;
                    }
                }
                else
                    BaseToken.Grant_Error = authorizeResponse.Content.ReadAsStringAsync().Result;

                return BaseToken;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }


        # endregion Grant_Methods
    }
}
