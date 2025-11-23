using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using OpenIdDict.ServerExample.Models;
using System.Net;

namespace OpenIdDict.ServerExample.Controllers;

public class AccountController : Controller
{
    private readonly IAuthenticationSchemeProvider _authenticationSchemeProvider;

    public AccountController(IAuthenticationSchemeProvider authenticationSchemeProvider)
    {
        _authenticationSchemeProvider = authenticationSchemeProvider;
    }

    public async Task<IActionResult> Login(string returnUrl)
    {
        var schemes = await _authenticationSchemeProvider.GetAllSchemesAsync();
        var providers = schemes
            .Where(x => x.DisplayName != null)
            .Select(x => new ExternalProvider(x.DisplayName ?? x.Name, x.Name));
        var sanitizedReturnUrl = WebUtility.HtmlEncode(returnUrl);
        var viewModel = new AccountLoginViewModel(providers, sanitizedReturnUrl);

        return View(viewModel);
    }

    public IActionResult ExternalLogin(string provider, string returnUrl)
    {
        var props = new AuthenticationProperties
        {
            RedirectUri = Url.Action(nameof(ExternalLoginCallback)),
            Items =
            {
                { "returnUrl", returnUrl },
                { "scheme", provider },
                { "cancelReturnUrl", Url.Action("Login", "Account", new { returnUrl }) }
            }
        };

        return Challenge(props, provider);
    }

    [HttpGet]
    public async Task<IActionResult> ExternalLoginCallback()
    {
        // Authenticate against the external scheme (BankID)
        var result = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        if (result?.Succeeded != true)
        {
            throw new Exception("External authentication error");
        }

        //// Get the external provider scheme that was used
        //var externalScheme = result.Properties?.Items["scheme"];
        //if (!string.IsNullOrEmpty(externalScheme))
        //{
        //    // Authenticate using the external scheme to get the claims
        //    var externalResult = await HttpContext.AuthenticateAsync(externalScheme);
        //    if (externalResult?.Succeeded == true)
        //    {
        //        // Sign in the user with the application cookie
        //        var claims = externalResult.Principal!.Claims.ToList();
        //        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        //        var principal = new ClaimsPrincipal(identity);

        //        await HttpContext.SignInAsync(
        //            CookieAuthenticationDefaults.AuthenticationScheme,
        //            principal,
        //            new AuthenticationProperties
        //            {
        //                IsPersistent = true,
        //                ExpiresUtc = DateTimeOffset.UtcNow.AddHours(1)
        //            });
        //    }
        //}

        var returnUrl = result.Properties?.Items["returnUrl"];

        if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
        {
            return Redirect(returnUrl);
        }

        return Redirect("~/");
    }

    [HttpGet]
    public async Task<IActionResult> Logout(string returnUrl)
    {
        return await Logout(new LogoutModel(returnUrl));
    }

    [HttpPost]
    public async Task<IActionResult> Logout(LogoutModel model)
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        return Redirect(model?.ReturnUrl ?? "~/");
    }

    public class LogoutModel
    {
        public LogoutModel() : this(null)
        {
        }

        public LogoutModel(string? returnUrl)
        {
            ReturnUrl = returnUrl;
        }

        public string? ReturnUrl { get; }
    }
}
