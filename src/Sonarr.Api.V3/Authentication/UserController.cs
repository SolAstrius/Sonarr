using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using NzbDrone.Common.Extensions;
using NzbDrone.Core.Authentication;
using NzbDrone.Core.Configuration;
using Sonarr.Http;

namespace Sonarr.Api.V3.Authentication
{
    // Who is signed in, for the UI to show.  Under OIDC this is whatever the
    // identity provider told us; under Forms it is the local account.
    [V3ApiController("user")]
    public class UserController : Controller
    {
        private readonly IConfigFileProvider _configFileProvider;

        public UserController(IConfigFileProvider configFileProvider)
        {
            _configFileProvider = configFileProvider;
        }

        [HttpGet]
        [Produces("application/json")]
        public UserResource GetUser()
        {
            var user = HttpContext.User;
            var method = _configFileProvider.AuthenticationMethod;

            var resource = new UserResource
            {
                AuthenticationMethod = method,
                IsAuthenticated = user?.Identity?.IsAuthenticated ?? false,
                Groups = new List<string>()
            };

            // NoAuthenticationHandler hands out an authenticated "Anonymous" principal,
            // so these two have to be reported as nobody rather than as a user.
            if (user == null || method is AuthenticationType.None or AuthenticationType.External)
            {
                resource.IsAuthenticated = false;

                return resource;
            }

            // Inbound JWT claims are partly remapped to the WS-* URIs, so both the
            // OIDC name and the mapped one have to be tried.
            resource.Username = FirstClaim(user, _configFileProvider.OidcUsernameClaim, "preferred_username", "user", ClaimTypes.Name);
            resource.Name = FirstClaim(user, "name", ClaimTypes.Name);
            resource.Email = FirstClaim(user, "email", ClaimTypes.Email);
            resource.Avatar = FirstClaim(user, "picture", "avatar");

            var groupsClaim = _configFileProvider.OidcGroupsClaim;

            resource.Groups = user.Claims
                .Where(c => c.Type == groupsClaim || c.Type == "groups" || c.Type == ClaimTypes.Role)
                .Select(c => c.Value)
                .Distinct()
                .ToList();

            // A local account has no display name of its own.
            if (resource.Name.IsNullOrWhiteSpace())
            {
                resource.Name = resource.Username;
            }

            return resource;
        }

        private static string FirstClaim(ClaimsPrincipal user, params string[] types)
        {
            foreach (var type in types)
            {
                if (type.IsNullOrWhiteSpace())
                {
                    continue;
                }

                var value = user.FindFirst(type)?.Value;

                if (value.IsNotNullOrWhiteSpace())
                {
                    return value;
                }
            }

            return null;
        }
    }
}
