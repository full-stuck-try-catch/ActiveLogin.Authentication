using System.Security.Claims;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIdDict.ServerExample.Controllers;

public class AuthorizationController : Controller
{
    [HttpGet("~/connect/authorize")]
    [HttpPost("~/connect/authorize")]
    public async Task<IActionResult> Authorize()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
        throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        // Retrieve the user principal stored in the authentication cookie
        var result = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        // If the user principal can't be extracted, redirect to the login page
        //if (!result.Succeeded)
        //{
            return Challenge(
                authenticationSchemes: CookieAuthenticationDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties
                {
                    RedirectUri = Request.PathBase + Request.Path + QueryString.Create(
                        Request.HasFormContentType ? Request.Form.ToList() : Request.Query.ToList())
                });
        //}

        //// Create the claims-based identity
        //var identity = new ClaimsIdentity(
        //    authenticationType: TokenValidationParameters.DefaultAuthenticationType,
        //    nameType: Claims.Name,
        //    roleType: Claims.Role);

        //// Get subject from BankID Personal Identity Number or NameIdentifier
        //var subject = result.Principal!.FindFirst(ActiveLogin.Authentication.BankId.AspNetCore.BankIdClaimTypes.SwedishPersonalIdentityNumber)?.Value
        //              ?? result.Principal.FindFirst(ClaimTypes.NameIdentifier)?.Value
        //              ?? result.Principal.FindFirst(Claims.Subject)?.Value;

        //if (string.IsNullOrEmpty(subject))
        //{
        //    throw new InvalidOperationException("The subject claim is required but was not found in the authentication result.");
        //}

        //// Add the subject claim (required by OpenIddict)
        //identity.AddClaim(Claims.Subject, subject);

        //// Add name claim
        //var name = result.Principal.FindFirst(ClaimTypes.Name)?.Value 
        //           ?? result.Principal.FindFirst(Claims.Name)?.Value;
        //if (!string.IsNullOrEmpty(name))
        //{
        //    identity.AddClaim(Claims.Name, name);
        //}

        //// Add given name and family name if available
        //var givenName = result.Principal.FindFirst(ClaimTypes.GivenName)?.Value
        //                ?? result.Principal.FindFirst(Claims.GivenName)?.Value;
        //if (!string.IsNullOrEmpty(givenName))
        //{
        //    identity.AddClaim(Claims.GivenName, givenName);
        //}

        //var familyName = result.Principal.FindFirst(ClaimTypes.Surname)?.Value
        //                 ?? result.Principal.FindFirst(Claims.FamilyName)?.Value;
        //if (!string.IsNullOrEmpty(familyName))
        //{
        //    identity.AddClaim(Claims.FamilyName, familyName);
        //}

        //// Add Swedish Personal Identity Number if requested
        //if (request.HasScope("personalidentitynumber"))
        //{
        //    var personalIdentityNumber = result.Principal.FindFirst(ActiveLogin.Authentication.BankId.AspNetCore.BankIdClaimTypes.SwedishPersonalIdentityNumber)?.Value;
        //    if (!string.IsNullOrEmpty(personalIdentityNumber))
        //    {
        //        identity.AddClaim(ActiveLogin.Authentication.BankId.AspNetCore.BankIdClaimTypes.SwedishPersonalIdentityNumber, personalIdentityNumber);
        //    }
        //}

        //// Set destinations for claims
        //identity.SetDestinations(GetDestinations);

        //// Create a new ClaimsPrincipal containing the claims
        //var principal = new ClaimsPrincipal(identity);

        //// Signing in with the OpenIddict authentification scheme trigger OpenIddict to issue a code (which can be exchanged for an access token)
        //return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    [HttpPost("~/connect/token")]
    public async Task<IActionResult> Exchange()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        if (request.IsAuthorizationCodeGrantType())
        {
            // Retrieve the claims principal stored in the authorization code
            var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            // Returning a SignInResult will ask OpenIddict to issue the appropriate access/identity tokens
            return SignIn(result.Principal!, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        throw new InvalidOperationException("The specified grant type is not supported.");
    }

    [HttpGet("~/connect/userinfo")]
    [HttpPost("~/connect/userinfo")]
    public async Task<IActionResult> Userinfo()
    {
        var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        if (!result.Succeeded)
        {
            return Challenge(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        var claims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [Claims.Subject] = result.Principal!.FindFirst(Claims.Subject)?.Value ?? string.Empty
        };

        if (result.Principal.HasClaim(c => c.Type == Claims.Name))
        {
            claims[Claims.Name] = result.Principal.FindFirst(Claims.Name)!.Value;
        }

        if (result.Principal.HasClaim(c => c.Type == Claims.GivenName))
        {
            claims[Claims.GivenName] = result.Principal.FindFirst(Claims.GivenName)!.Value;
        }

        if (result.Principal.HasClaim(c => c.Type == Claims.FamilyName))
        {
            claims[Claims.FamilyName] = result.Principal.FindFirst(Claims.FamilyName)!.Value;
        }

        if (result.Principal.HasClaim(c => c.Type == ActiveLogin.Authentication.BankId.AspNetCore.BankIdClaimTypes.SwedishPersonalIdentityNumber))
        {
            claims[ActiveLogin.Authentication.BankId.AspNetCore.BankIdClaimTypes.SwedishPersonalIdentityNumber] = 
                result.Principal.FindFirst(ActiveLogin.Authentication.BankId.AspNetCore.BankIdClaimTypes.SwedishPersonalIdentityNumber)!.Value;
        }

        return Ok(claims);
    }

    [HttpGet("~/connect/logout")]
    [HttpPost("~/connect/logout")]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        return SignOut(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private static IEnumerable<string> GetDestinations(Claim claim)
    {
        // Include claim in both access tokens and identity tokens
        switch (claim.Type)
        {
            case Claims.Name:
            case Claims.Subject:
            case Claims.GivenName:
            case Claims.FamilyName:
                yield return Destinations.AccessToken;
                yield return Destinations.IdentityToken;
                yield break;

            case "swedish_personal_identity_number":
                // Include Swedish Personal Identity Number in both tokens if present
                yield return Destinations.AccessToken;
                yield return Destinations.IdentityToken;
                yield break;

            default:
                // Include claim in access token only
                yield return Destinations.AccessToken;
                yield break;
        }
    }
}
