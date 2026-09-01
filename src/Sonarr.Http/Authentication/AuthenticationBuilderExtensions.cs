using System;
using System.Linq;
using System.Security.Claims;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Diacritical;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using NzbDrone.Common.Extensions;
using NzbDrone.Core.Authentication;
using NzbDrone.Core.Configuration;

namespace Sonarr.Http.Authentication
{
    public static class AuthenticationBuilderExtensions
    {
        // The remote OpenIdConnect handler cannot be an authenticate scheme: it
        // challenges, and the identity it produces lands in a cookie.  But the "UI"
        // policy names a single scheme, the ToString() of the configured method.  So
        // the scheme called "Oidc" is a *cookie*, and it forwards its challenge here.
        public const string OidcRemoteScheme = "OidcRemote";

        private static readonly Regex CookieNameRegex = new Regex(@"[^a-z0-9]+", RegexOptions.Compiled | RegexOptions.IgnoreCase);

        public static AuthenticationBuilder AddApiKey(this AuthenticationBuilder authenticationBuilder, string name, Action<ApiKeyAuthenticationOptions> options)
        {
            return authenticationBuilder.AddScheme<ApiKeyAuthenticationOptions, ApiKeyAuthenticationHandler>(name, options);
        }

        public static AuthenticationBuilder AddBasic(this AuthenticationBuilder authenticationBuilder, string name)
        {
            return authenticationBuilder.AddScheme<AuthenticationSchemeOptions, BasicAuthenticationHandler>(name, options => { });
        }

        public static AuthenticationBuilder AddNone(this AuthenticationBuilder authenticationBuilder, string name)
        {
            return authenticationBuilder.AddScheme<AuthenticationSchemeOptions, NoAuthenticationHandler>(name, options => { });
        }

        public static AuthenticationBuilder AddExternal(this AuthenticationBuilder authenticationBuilder, string name)
        {
            return authenticationBuilder.AddScheme<AuthenticationSchemeOptions, NoAuthenticationHandler>(name, options => { });
        }

        public static AuthenticationBuilder AddAppAuthentication(this IServiceCollection services, IConfiguration configuration)
        {
            // The OpenIdConnect handler is an IAuthenticationRequestHandler, so it is
            // constructed on every request and validates its options as it goes.  With no
            // client id that validation throws, which would 500 the whole app, so the
            // remote scheme is only registered once it is actually configured.
            var oidcConfigured = (configuration["Sonarr:Auth:OidcClientId"] ?? configuration["OidcClientId"]).IsNotNullOrWhiteSpace();

            services.AddOptions<CookieAuthenticationOptions>(AuthenticationType.Forms.ToString())
                .Configure<IConfigFileProvider>((options, configFileProvider) =>
                {
                    options.Cookie.Name = GetCookieName(configFileProvider);
                    options.Cookie.SameSite = SameSiteMode.Lax;
                    options.AccessDeniedPath = "/login?loginFailed=true";
                    options.LoginPath = "/login";
                    options.ExpireTimeSpan = TimeSpan.FromDays(7);
                    options.SlidingExpiration = true;
                    options.ReturnUrlParameter = "returnUrl";

                    // Now that this scheme also guards the API, an unauthenticated API
                    // call must answer 401 rather than redirect a machine client into
                    // the login page.
                    options.Events.OnRedirectToLogin = context =>
                    {
                        if (IsApiRequest(context.Request, configFileProvider.UrlBase))
                        {
                            context.Response.StatusCode = 401;
                            return Task.CompletedTask;
                        }

                        context.Response.Redirect(context.RedirectUri);
                        return Task.CompletedTask;
                    };
                });

            services.AddOptions<CookieAuthenticationOptions>(AuthenticationType.Oidc.ToString())
                .Configure<IConfigFileProvider>((options, configFileProvider) =>
                {
                    options.Cookie.Name = GetCookieName(configFileProvider);

                    // Lax keeps the cookie off cross-site subresource requests, which is
                    // what stops the API accepting it from a hostile page now that a
                    // session authenticates API calls (see Startup.cs).
                    options.Cookie.SameSite = SameSiteMode.Lax;
                    options.ExpireTimeSpan = TimeSpan.FromDays(7);
                    options.SlidingExpiration = true;
                    options.ReturnUrlParameter = "returnUrl";

                    // Anything that would have shown the local login form instead starts
                    // the authorization-code flow at the identity provider -- except an
                    // API call, which gets a 401 like it always did.  This is done per
                    // request rather than with ForwardChallenge precisely so the two
                    // cases can be told apart.
                    options.Events.OnRedirectToLogin = context =>
                    {
                        if (IsApiRequest(context.Request, configFileProvider.UrlBase) ||
                            configFileProvider.OidcClientId.IsNullOrWhiteSpace())
                        {
                            context.Response.StatusCode = 401;
                            return Task.CompletedTask;
                        }

                        return context.HttpContext.ChallengeAsync(OidcRemoteScheme);
                    };
                });

            services.AddOptions<OpenIdConnectOptions>(OidcRemoteScheme)
                .Configure<IConfigFileProvider>((options, configFileProvider) =>
                {
                    var urlBase = configFileProvider.UrlBase ?? string.Empty;

                    options.Authority = configFileProvider.OidcAuthority;
                    options.ClientId = configFileProvider.OidcClientId;
                    options.ClientSecret = configFileProvider.OidcClientSecret;

                    // Where the resulting identity is stored: the cookie the UI policy reads.
                    options.SignInScheme = AuthenticationType.Oidc.ToString();

                    options.ResponseType = OpenIdConnectResponseType.Code;
                    options.UsePkce = true;
                    options.SaveTokens = false;
                    options.GetClaimsFromUserInfoEndpoint = true;
                    options.RequireHttpsMetadata = options.Authority?.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ?? true;

                    options.CallbackPath = new PathString(urlBase + "/signin-oidc");
                    options.SignedOutCallbackPath = new PathString(urlBase + "/signout-callback-oidc");
                    options.RemoteSignOutPath = new PathString(urlBase + "/signout-oidc");

                    options.Scope.Clear();
                    foreach (var scope in (configFileProvider.OidcScopes ?? string.Empty).Split(new[] { ' ', ',' }, StringSplitOptions.RemoveEmptyEntries))
                    {
                        options.Scope.Add(scope);
                    }

                    options.TokenValidationParameters.NameClaimType = configFileProvider.OidcUsernameClaim;
                    options.TokenValidationParameters.RoleClaimType = configFileProvider.OidcGroupsClaim;

                    options.Events = new OpenIdConnectEvents
                    {
                        OnTicketReceived = context =>
                        {
                            var principal = context.Principal;
                            var requiredGroup = configFileProvider.OidcRequiredGroup;
                            var groupsClaim = configFileProvider.OidcGroupsClaim;

                            if (requiredGroup.IsNotNullOrWhiteSpace() &&
                                !principal.Claims.Any(c => c.Type == groupsClaim && c.Value == requiredGroup))
                            {
                                context.Fail($"User is not a member of '{requiredGroup}'");
                                return Task.CompletedTask;
                            }

                            // Match the claim shape the rest of the app expects from Forms
                            // login, so logging and the logout path behave identically.
                            var username = principal.FindFirst(configFileProvider.OidcUsernameClaim)?.Value
                                           ?? principal.FindFirst(ClaimTypes.Name)?.Value
                                           ?? "Unknown";

                            var identity = new ClaimsIdentity(new[]
                            {
                                new Claim("user", username),
                                new Claim("identifier", principal.FindFirst("sub")?.Value ?? username),
                                new Claim("AuthType", AuthenticationType.Oidc.ToString())
                            });

                            principal.AddIdentity(identity);

                            return Task.CompletedTask;
                        }
                    };
                });

            var builder = services.AddAuthentication()
                .AddNone(AuthenticationType.None.ToString())
                .AddExternal(AuthenticationType.External.ToString())
                .AddBasic(AuthenticationType.Basic.ToString())
                .AddCookie(AuthenticationType.Forms.ToString())
                .AddCookie(AuthenticationType.Oidc.ToString())
                .AddApiKey("API", options =>
                {
                    options.HeaderName = "X-Api-Key";
                    options.QueryName = "apikey";
                })
                .AddApiKey("SignalR", options =>
                {
                    options.HeaderName = "X-Api-Key";
                    options.QueryName = "access_token";
                });

            if (oidcConfigured)
            {
                builder.AddOpenIdConnect(OidcRemoteScheme, options => { });
            }

            return builder;
        }

        private static bool IsApiRequest(HttpRequest request, string urlBase)
        {
            var path = request.Path.Value ?? string.Empty;

            if (urlBase.IsNotNullOrWhiteSpace() && path.StartsWith(urlBase, StringComparison.OrdinalIgnoreCase))
            {
                path = path.Substring(urlBase.Length);
            }

            return path.StartsWith("/api/", StringComparison.OrdinalIgnoreCase) ||
                   path.StartsWith("/feed/", StringComparison.OrdinalIgnoreCase) ||
                   path.StartsWith("/signalr/", StringComparison.OrdinalIgnoreCase);
        }

        private static string GetCookieName(IConfigFileProvider configFileProvider)
        {
            // Replace diacritics and replace non-word characters to ensure cookie name doesn't contain any valid URL characters not allowed in cookie names
            var instanceName = configFileProvider.InstanceName;
            instanceName = instanceName.RemoveDiacritics();
            instanceName = CookieNameRegex.Replace(instanceName, string.Empty);

            return $"{instanceName}Auth";
        }
    }
}
