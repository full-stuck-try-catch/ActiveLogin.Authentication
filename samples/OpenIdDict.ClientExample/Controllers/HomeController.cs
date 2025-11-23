using System.Diagnostics;
using System.Security.Claims;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

using OpenIdDict.ClientExample.Models;

namespace OpenIdDict.ClientExample.Controllers;
public class HomeController : Controller
{
    private readonly ILogger<HomeController> _logger;

    public HomeController(ILogger<HomeController> logger)
    {
        _logger = logger;
    }

    [Authorize]
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

    public IActionResult Privacy()
    {
        return View();
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}
