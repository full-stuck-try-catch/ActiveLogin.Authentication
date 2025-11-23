using ActiveLogin.Authentication.BankId.AspNetCore;
using OpenIddict.Abstractions;

namespace OpenIdDict.ServerExample;

public static class OpenIddictConfig
{
    private const string PersonalIdentityNumberScopeName = "personalidentitynumber";

    public static async Task RegisterClientsAndScopesAsync(IServiceProvider provider, IConfiguration clientsConfiguration)
    {
        var scopeManager = provider.GetRequiredService<IOpenIddictScopeManager>();
        var applicationManager = provider.GetRequiredService<IOpenIddictApplicationManager>();

        // Register scopes
        if (await scopeManager.FindByNameAsync(OpenIddictConstants.Scopes.OpenId) == null)
        {
            await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
            {
                Name = OpenIddictConstants.Scopes.OpenId,
                Resources = { "resource_server" }
            });
        }

        if (await scopeManager.FindByNameAsync(OpenIddictConstants.Scopes.Profile) == null)
        {
            await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
            {
                Name = OpenIddictConstants.Scopes.Profile,
                Resources = { "resource_server" }
            });
        }

        if (await scopeManager.FindByNameAsync(PersonalIdentityNumberScopeName) == null)
        {
            await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
            {
                Name = PersonalIdentityNumberScopeName,
                DisplayName = "Personal Identity Number",
                Resources = { "resource_server" }
            });
        }

        // Register MVC client
        var clientId = clientsConfiguration["MvcClient:ClientId"] ?? string.Empty;
        var existingClient = await applicationManager.FindByClientIdAsync(clientId);

        if (existingClient == null)
        {
            await applicationManager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = clientId,
                ClientSecret = clientsConfiguration["MvcClient:ClientSecret"],
                DisplayName = "Active Login - OpenIddict - MvcClientSample",
                ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
                RedirectUris =
                {
                    new Uri(clientsConfiguration["MvcClient:RedirectUri"] ?? "https://localhost:7101/signin-oidc")
                },
                PostLogoutRedirectUris =
                {
                    new Uri(clientsConfiguration["MvcClient:PostLogoutRedirectUri"] ?? "https://localhost:7101/signout-callback-oidc")
                },
                Permissions =
                {
                    // Grant types
                    OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,

                    // Endpoints
                    OpenIddictConstants.Permissions.Endpoints.Authorization,
                    OpenIddictConstants.Permissions.Endpoints.Token,
                    OpenIddictConstants.Permissions.Endpoints.Logout,

                    // Response types
                    OpenIddictConstants.Permissions.ResponseTypes.Code,

                    // Scopes
                    $"{OpenIddictConstants.Permissions.Prefixes.Scope}{OpenIddictConstants.Scopes.OpenId}",
                    $"{OpenIddictConstants.Permissions.Prefixes.Scope}{OpenIddictConstants.Scopes.Profile}",
                    $"{OpenIddictConstants.Permissions.Prefixes.Scope}{PersonalIdentityNumberScopeName}"
                },
                Requirements =
                {
                    OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange
                }
            });
        }
    }
}
