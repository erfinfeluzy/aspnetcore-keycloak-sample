using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using System.Security.Claims;

namespace AspNetCoreGitHubAuth.Pages
{
    public class IndexModel : PageModel
    {
        

        public string KeycloakName { get; set; }

        public string KeycloakEmail { get; set; }

        public string KeycloakPreferredUsername { get; set; }

        public string KeycloakGivenName { get; set; }

        public string KeycloakFamilyName { get; set; }


        public void OnGet()
        {
            if (User.Identity.IsAuthenticated)
            {
                KeycloakName = User.FindFirst(c => c.Type == ClaimTypes.Name)?.Value;
                KeycloakEmail = User.FindFirst(c => c.Type == "urn:keycloak:email")?.Value;
                KeycloakPreferredUsername = User.FindFirst(c => c.Type == "urn:keycloak:preferred_username")?.Value;
                KeycloakGivenName = User.FindFirst(c => c.Type == "urn:keycloak:given_name")?.Value;
                KeycloakFamilyName = User.FindFirst(c => c.Type == "urn:keycloak:family_name")?.Value;

            }
        }
    }
}
