using System.Globalization;
using System.Text;
using ActiveLogin.Authentication.BankId.Api;
using ActiveLogin.Authentication.BankId.AspNetCore.Auth;
using ActiveLogin.Authentication.BankId.AzureKeyVault;
using ActiveLogin.Authentication.BankId.Core;
using ActiveLogin.Authentication.BankId.QrCoder;
using ActiveLogin.Authentication.BankId.UaParser;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.CookiePolicy;
using Microsoft.AspNetCore.Localization;
using Microsoft.EntityFrameworkCore;
using OpenIdDict.ServerExample;

var builder = WebApplication.CreateBuilder(args);

var services = builder.Services;
var configuration = builder.Configuration;
var environment = builder.Environment;

// Configure cookie policy
services.Configure<CookiePolicyOptions>(options =>
{
    options.MinimumSameSitePolicy = SameSiteMode.None;
    options.HttpOnly = HttpOnlyPolicy.Always;
    options.Secure = CookieSecurePolicy.Always;
});

//// Add custom antiforgery data provider that allows authentication state changes
//services.AddSingleton<IAntiforgeryAdditionalDataProvider, BankIdAntiforgeryAdditionalDataProvider>();

//// Configure Antiforgery
//services.AddAntiforgery(options =>
//{
//    options.Cookie.Name = "OpenIdDict.Antiforgery";
//    options.Cookie.SameSite = SameSiteMode.None;
//    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
//});

// Add DbContext with In-Memory database for OpenIddict
services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseInMemoryDatabase("OpenIddictDb");
    options.UseOpenIddict();
});

// Add OpenIddict
services.AddOpenIddict()
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore()
            .UseDbContext<ApplicationDbContext>();
    })
    .AddServer(options =>
    {
        // Enable the authorization, token, and logout endpoints
        options.SetAuthorizationEndpointUris("/connect/authorize")
            .SetTokenEndpointUris("/connect/token")
            .SetLogoutEndpointUris("/connect/logout")
            .SetUserinfoEndpointUris("/connect/userinfo");

        // Enable the authorization code flow
        options.AllowAuthorizationCodeFlow()
            .RequireProofKeyForCodeExchange();

        // Register claims
        options.RegisterClaims(
            OpenIddict.Abstractions.OpenIddictConstants.Claims.Name,
            OpenIddict.Abstractions.OpenIddictConstants.Claims.GivenName,
            OpenIddict.Abstractions.OpenIddictConstants.Claims.FamilyName,
            ActiveLogin.Authentication.BankId.AspNetCore.BankIdClaimTypes.SwedishPersonalIdentityNumber
        );

        // Register scopes
        options.RegisterScopes(
            OpenIddict.Abstractions.OpenIddictConstants.Scopes.OpenId,
            OpenIddict.Abstractions.OpenIddictConstants.Scopes.Profile,
            "personalidentitynumber"
        );

        // Register signing and encryption credentials
        options.AddDevelopmentEncryptionCertificate()
            .AddDevelopmentSigningCertificate();

        // Register ASP.NET Core host
        options.UseAspNetCore()
            .EnableAuthorizationEndpointPassthrough()
            .EnableTokenEndpointPassthrough()
            .EnableLogoutEndpointPassthrough()
            .EnableUserinfoEndpointPassthrough();

        options.DisableAccessTokenEncryption();
    });

// Add Active Login - BankID
services
    .AddBankId(bankId =>
    {
        bankId.AddDebugEventListener();
        bankId.UseQrCoderQrCodeGenerator();
        bankId.UseUaParserDeviceDetection();

        if (configuration.GetValue("ActiveLogin:BankId:UseSimulatedEnvironment", false))
        {
            bankId.UseSimulatedEnvironment();
        }
        else if (configuration.GetValue("ActiveLogin:BankId:UseTestEnvironment", false))
        {
            bankId.UseTestEnvironment();
        }
        else
        {
            bankId.UseProductionEnvironment();
            bankId.UseClientCertificateFromAzureKeyVault(configuration.GetSection("ActiveLogin:BankId:ClientCertificate"));
        }
    });

// Add authentication
services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddBankIdAuth(bankId =>
    {
        bankId.AddSameDevice(BankIdAuthDefaults.SameDeviceAuthenticationScheme, "BankID (Same Device)", options => { });
        bankId.AddOtherDevice(BankIdAuthDefaults.OtherDeviceAuthenticationScheme, "BankID (Other Device)", options => { });
        bankId.UseAuthRequestUserData(authUserData =>
        {
            var message = new StringBuilder();
            message.AppendLine("# Active Login");
            message.AppendLine();
            message.AppendLine("Welcome to the *Active Login* demo with OpenIddict.");

            authUserData.UserVisibleData = message.ToString();
            authUserData.UserVisibleDataFormat = BankIdUserVisibleDataFormats.SimpleMarkdownV1;
        });
    });

// Add MVC
services.AddControllersWithViews();

// Build app
var app = builder.Build();

// Initialize OpenIddict data
using (var scope = app.Services.CreateScope())
{
    var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    await context.Database.EnsureCreatedAsync();

    await OpenIddictConfig.RegisterClientsAndScopesAsync(
        scope.ServiceProvider,
        configuration.GetSection("ActiveLogin:Clients")
    );
}

if (environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}

if (!environment.IsDevelopment())
{
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRequestLocalization(options =>
{
    var supportedCultures = new List<CultureInfo>
    {
        new CultureInfo("en-US"),
        new CultureInfo("en"),
        new CultureInfo("sv-SE"),
        new CultureInfo("sv")
    };

    options.DefaultRequestCulture = new RequestCulture("en-US");
    options.SupportedCultures = supportedCultures;
    options.SupportedUICultures = supportedCultures;
});

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.MapDefaultControllerRoute();

app.Run();
