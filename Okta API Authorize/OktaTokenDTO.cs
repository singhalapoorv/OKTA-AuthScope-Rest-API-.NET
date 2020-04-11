using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Rainier.Models.Domain
{
    public class OktaTokenDTO
    {
        public SessionToken SessionToken
        {
            get { return _sessionToken; }
            set { _sessionToken = value; }
        }
        public AccessToken AccessToken
        {
            get { return _accessToken; }
            set { _accessToken = value; }
        }
        public IDToken IDToken
        {
            get { return _idToken; }
            set { _idToken = value; }
        }
        public RefreshToken RefreshToken
        {
            get { return _refreshToken; }
            set { _refreshToken = value; }
        }
        [JsonProperty(PropertyName = "vault_token", NullValueHandling = NullValueHandling.Ignore)]
        public string VaultToken { get; set; }
        [JsonProperty(PropertyName = "scope", NullValueHandling = NullValueHandling.Ignore)]
        public string Scope { get; set; }
        [JsonProperty(PropertyName = "authenticationstatus", NullValueHandling = NullValueHandling.Ignore)]
        public string AuthenticationStatus { get; set; }
        [JsonProperty(PropertyName = "factors", NullValueHandling = NullValueHandling.Ignore)]
        public dynamic Factors { get; set; }
        [JsonProperty(PropertyName = "statetoken", NullValueHandling = NullValueHandling.Ignore)]
        public String StateToken { get; set; }
        [JsonProperty(PropertyName = "token_type", NullValueHandling = NullValueHandling.Ignore)]
        public string TokenType { get; set; }
        [JsonProperty(PropertyName = "grant_error", NullValueHandling = NullValueHandling.Ignore)]
        public string Grant_Error { get; set; }
        [JsonProperty(PropertyName = "tenant", NullValueHandling = NullValueHandling.Ignore)]
        public string Tenant { get; set; }
        [JsonIgnore]
        public System.Net.CookieCollection Cookies { get; set; }
        [JsonIgnore]
        public string SessionId { get; set; }
        private SessionToken _sessionToken = new SessionToken();
        private AccessToken _accessToken = new AccessToken();
        private IDToken _idToken = new IDToken();
        private RefreshToken _refreshToken = new RefreshToken();
    }

    public class SessionToken
    {
        [JsonProperty(PropertyName = "session_token", NullValueHandling = NullValueHandling.Ignore)]
        public string Value { get; set; }
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, PropertyName = "expires_at", NullValueHandling = NullValueHandling.Ignore)]
        public DateTimeOffset? ExpiresAt { get; set; }
    }

    public class AccessToken
    {
        [JsonProperty(PropertyName = "access_token", NullValueHandling = NullValueHandling.Ignore)]
        public string Value { get; set; }
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, PropertyName = "expires_in", NullValueHandling = NullValueHandling.Ignore)]
        public int Expires_In { get; set; }
    }

    public class IDToken
    {
        [JsonProperty(PropertyName = "id_token", NullValueHandling = NullValueHandling.Ignore)]
        public string Value { get; set; }
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, PropertyName = "expires_in", NullValueHandling = NullValueHandling.Ignore)]
        public int Expires_In { get; set; }
    }

    public class RefreshToken
    {
        [JsonProperty(PropertyName = "refresh_token", NullValueHandling = NullValueHandling.Ignore)]
        public string Value { get; set; }
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, PropertyName = "expires_in", NullValueHandling = NullValueHandling.Ignore)]
        public int Expires_In { get; set; }
    }
}
