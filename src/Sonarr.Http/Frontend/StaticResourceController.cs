using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Mvc;
using NLog;
using NzbDrone.Core.Authentication;
using NzbDrone.Core.Configuration;
using Sonarr.Http.Extensions;
using Sonarr.Http.Frontend.Mappers;

namespace Sonarr.Http.Frontend
{
    [Authorize(Policy="UI")]
    [ApiController]
    public class StaticResourceController : Controller
    {
        private readonly IEnumerable<IMapHttpRequestsToDisk> _requestMappers;
        private readonly IConfigFileProvider _configFileProvider;
        private readonly Logger _logger;
        private static readonly Regex InvalidPathRegex = new (@"([\/\\]|%2f|%5c)\.\.|\.\.([\/\\]|%2f|%5c)", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        public StaticResourceController(IEnumerable<IMapHttpRequestsToDisk> requestMappers,
            IConfigFileProvider configFileProvider,
            Logger logger)
        {
            _requestMappers = requestMappers;
            _configFileProvider = configFileProvider;
            _logger = logger;
        }

        [AllowAnonymous]
        [HttpGet("login")]
        public async Task<IActionResult> LoginPage()
        {
            // Under OIDC there is no local form to show: bounce straight into the
            // authorization-code flow.  The cookie scheme forwards the challenge to
            // the remote handler (see AuthenticationBuilderExtensions).
            if (_configFileProvider.AuthenticationMethod == AuthenticationType.Oidc)
            {
                return Challenge(
                    new AuthenticationProperties { RedirectUri = _configFileProvider.UrlBase + "/" },
                    AuthenticationType.Oidc.ToString());
            }

            return await MapResource("login");
        }

        [EnableCors("AllowGet")]
        [AllowAnonymous]
        [HttpGet("/content/{**path:regex(^(?!api/).*)}")]
        public async Task<IActionResult> IndexContent([FromRoute] string path)
        {
            return await MapResource("Content/" + path);
        }

        [HttpGet("")]
        [HttpGet("/{**path:regex(^(?!(api|feed)/).*)}")]
        public async Task<IActionResult> Index([FromRoute] string path)
        {
            return await MapResource(path);
        }

        private async Task<IActionResult> MapResource(string path)
        {
            path = "/" + (path ?? "");

            if (InvalidPathRegex.IsMatch(path))
            {
                return NotFound();
            }

            var mapper = _requestMappers.SingleOrDefault(m => m.CanHandle(path));

            if (mapper != null)
            {
                var result = await mapper.GetResponse(path);

                if (result != null)
                {
                    if ((result as FileResult)?.ContentType == "text/html")
                    {
                        Response.Headers.DisableCache();
                    }

                    return result;
                }

                return NotFound();
            }

            _logger.Warn("Couldn't find handler for {0}", path);

            return NotFound();
        }
    }
}
