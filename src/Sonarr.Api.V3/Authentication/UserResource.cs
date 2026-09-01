using System.Collections.Generic;
using NzbDrone.Core.Authentication;

namespace Sonarr.Api.V3.Authentication
{
    public class UserResource
    {
        public AuthenticationType AuthenticationMethod { get; set; }
        public bool IsAuthenticated { get; set; }
        public string Username { get; set; }
        public string Name { get; set; }
        public string Email { get; set; }
        public string Avatar { get; set; }
        public List<string> Groups { get; set; }
    }
}
