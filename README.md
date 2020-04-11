# OKTA-AuthScope-Rest-API-C-
Setting up authorization scopes in Okta to authorize rest api's in a .NET project

The AuthorizeScopeAttribute class provides ability to define custom authorization scope on an API.
It checks for the session ID of the user which was generated after the user was Authenticated.
This session ID is used along with the scope on the API to see if the current User is authorized to use the API or not.

The AuthorizationCode class provides different Authorizarion Code Flows like PKCE, Default Server, Custom Server.
We are using the Custom Server Flow here.
You'll find different custom OKTA fields in the Default_Authorization_Server_Code_Flow method which you'll have to provide as per your OKTA server properties.

Note: This is a working code. I have included all the methods required to run it.

Just provide an attribute on top of your API action method like [AuthorizeScope("scopename")]



