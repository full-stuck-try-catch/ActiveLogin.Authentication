using System.Diagnostics;
using System.Security.Claims;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

using OpenIdDict.ServerExample.Models;

namespace OpenIdDict.ServerExample.Controllers;

[Authorize]
public class HomeController : Controller
{

    public HomeController()
    {
    }

    public IActionResult Index()
    {
        var claims = User.Claims.ToList();
        var viewModel = new HomeIndexViewModel(
            GetClaimValue(claims, "given_name"),
            GetClaimValue(claims, "family_name"),
            GetClaimValue(claims, "name"),
            GetClaimValue(claims, "swedish_personal_identity_number"),
            GetClaimValue(claims, "birthdate"),
            GetClaimValue(claims, "gender"),
            claims
        );

        return View(viewModel);
    }


    private string GetClaimValue(IEnumerable<Claim> claims, string type, string fallback = "-")
    {
        return claims.FirstOrDefault(x => x.Type == type)?.Value ?? fallback;
    }
}
