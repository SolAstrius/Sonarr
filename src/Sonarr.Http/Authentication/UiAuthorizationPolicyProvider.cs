using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using NzbDrone.Core.Configuration;

namespace NzbDrone.Http.Authentication
{
    public class UiAuthorizationPolicyProvider : IAuthorizationPolicyProvider
    {
        private const string POLICY_NAME = "UI";
        private const string SIGNALR_POLICY_NAME = "SignalR";
        private const string API_SCHEME = "API";
        private const string SIGNALR_SCHEME = "SignalR";
        private readonly IConfigFileProvider _config;

        public DefaultAuthorizationPolicyProvider FallbackPolicyProvider { get; }

        public UiAuthorizationPolicyProvider(IOptions<AuthorizationOptions> options,
            IConfigFileProvider config)
        {
            FallbackPolicyProvider = new DefaultAuthorizationPolicyProvider(options);
            _config = config;
        }

        public Task<AuthorizationPolicy> GetDefaultPolicyAsync() => FallbackPolicyProvider.GetDefaultPolicyAsync();

        // Everything not marked [AllowAnonymous] and not carrying its own policy:
        // the API surface.
        public Task<AuthorizationPolicy> GetFallbackPolicyAsync() => Task.FromResult(BuildApiPolicy(API_SCHEME));

        public Task<AuthorizationPolicy> GetPolicyAsync(string policyName)
        {
            if (policyName.Equals(POLICY_NAME, StringComparison.OrdinalIgnoreCase))
            {
                var policy = new AuthorizationPolicyBuilder(_config.AuthenticationMethod.ToString())
                    .AddRequirements(new BypassableDenyAnonymousAuthorizationRequirement());

                return Task.FromResult(policy.Build());
            }

            if (policyName.Equals(SIGNALR_POLICY_NAME, StringComparison.OrdinalIgnoreCase))
            {
                return Task.FromResult(BuildApiPolicy(SIGNALR_SCHEME));
            }

            return FallbackPolicyProvider.GetPolicyAsync(policyName);
        }

        // The API accepts the API key, or whatever currently authenticates the UI.
        // Both halves matter: machine clients (Prowlarr, arr-mcp, exportarr) hold a
        // key, and the UI no longer holds one at all -- including when the method is
        // None or External, where the scheme admits everyone exactly as the UI does.
        private AuthorizationPolicy BuildApiPolicy(string keyScheme)
        {
            return new AuthorizationPolicyBuilder(keyScheme, _config.AuthenticationMethod.ToString())
                .RequireAuthenticatedUser()
                .Build();
        }
    }
}
