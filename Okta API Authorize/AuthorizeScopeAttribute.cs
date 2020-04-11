using Microsoft.Owin;
using Microsoft.Practices.Unity;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.ServiceModel.Channels;
using System.Threading;
using System.Web;
using System.Web.Http;
using System.Web.Http.Controllers;

namespace RestApi.Infrastructure.ActionFilters
{
    public class AuthorizeScopeAttribute : AuthorizeAttribute
    {
        [Dependency]
        public ISecurityService _securitySvc { get; set; }

        private HttpResponseMessage _responseMessage = null;
        public HttpResponseMessage response
        {
            get { return _responseMessage; }
            set { _responseMessage = value; }
        }

        private string _actionScope = null;

        /// <summary>
        /// Sets first custom scope
        /// </summary>
        /// <param name="scope"></param>
        private AuthorizeScopeAttribute(string scope)
        {
            if (string.IsNullOrWhiteSpace(scope))
            {
                throw new ArgumentNullException("Scope");
            }
            this._actionScope = CreateCustomScope(scope);
        }

        /// <summary>
        /// For authorizing one or more than one scopes
        /// </summary>
        /// <param name="otherScopes"></param>
        public AuthorizeScopeAttribute(string scope, params string[] otherScopes)
            : this(scope)
        {
            foreach (var otherScope in otherScopes)
            {
                string customScope = CreateCustomScope(otherScope);
                this._actionScope += " " + customScope;
            }
            this._actionScope = this._actionScope.Trim();
        }

        public override void OnAuthorization(HttpActionContext actionContext)
        {
            return;
            var sid = GetSessionCookie(actionContext);
            if (Thread.CurrentPrincipal.Identity.IsAuthenticated)
            {
                string login = Thread.CurrentPrincipal.Identity.Name;

                var authrizationResult = AuthorizeCustomScope(sid, this._actionScope);
                if (string.Equals(authrizationResult.AuthenticationStatus, "SUCCESS", StringComparison.InvariantCultureIgnoreCase))
                {
                    AttachAccessTokenToRequest(authrizationResult, actionContext);
                    EventViewerLogManager.WriteInfo("RestAPI", string.Format("Authorized Successfully: Access granted to user {0} for scope: {1}, under session: {2}", login, this._actionScope, sid));
                    return;
                }
                else
                {
                    EventViewerLogManager.WriteWarning("RestAPI", string.Format("Authorization Failed: Access blocked to user {0} for scope: {1}, under session: {2}", login, this._actionScope, sid), Environment.StackTrace);
                    response = new HttpResponseMessage(HttpStatusCode.Unauthorized) { ReasonPhrase = "Unauthorized access to resource." };
                    HandleUnauthorizedRequest(actionContext);
                }
            }
            else
            {
                EventViewerLogManager.WriteWarning("RestAPI", string.Format("Authorization Failed: Request is not authenticated. Access blocked to scope {0} under SessionId {1}.", this._actionScope, sid), Environment.StackTrace);
                response = new HttpResponseMessage(HttpStatusCode.Unauthorized) { ReasonPhrase = "Invalid or expired session." };
                HandleUnauthorizedRequest(actionContext);
            }
        }

        private void AttachAccessTokenToRequest(Models.Domain.OktaTokenDTO authrizationResult, HttpActionContext actionContext)
        {
            actionContext.Request.Headers.Add("accesstoken", authrizationResult.AccessToken.Value);
        }

        private string CreateCustomScope(string scope)
        {
            string customScope = string.Format("{1}", scope);
            return customScope;
        }

        private string GetSessionCookie(HttpActionContext actionContext)
        {
            var sidCookie = actionContext.Request.Headers.GetCookies("sid").FirstOrDefault();
            if (sidCookie == null)
            {
                return string.Empty;
            }
            return sidCookie["sid"].Value;
        }


        protected override void HandleUnauthorizedRequest(HttpActionContext actionContext)
        {
            if (response == null)
                actionContext.Response = new HttpResponseMessage(HttpStatusCode.Unauthorized);
            else
                actionContext.Response = response;
        }
		
		 public OktaTokenDTO AuthorizeCustomScope(String sessionId, String customScope)
        {
            var result = AuthorizeCustomScope(sessionId, customScope);
            return result;
            

        }
		
		private OktaTokenDTO AuthorizeCustomScope(string sessionId, string customScope)
        {
            AuthorizationCode auth_Code = new AuthorizationCode(OktaDefaultAuthorizationServer);
            OktaTokenDTO baseToken = new OktaTokenDTO()
            {
                SessionId = sessionId
            };
            auth_Code.Custom_Authorization_Server_Code_Flow(baseToken, customScope);
            return baseToken;
        }
		
		private String OktaDefaultAuthorizationServer
        {
            get
            {
                if (!String.IsNullOrEmpty(OktaIdentityServer))
                {
                    if (!String.IsNullOrEmpty(_defaultAuthServerID))
                        return OktaIdentityServer + "/oauth2/" + _defaultAuthServerID;
                    else
                        return string.Empty;
                }
                else
                    return string.Empty;
            }
        }

    }
}