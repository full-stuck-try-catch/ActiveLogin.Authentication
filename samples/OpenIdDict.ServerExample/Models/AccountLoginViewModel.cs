namespace OpenIdDict.ServerExample.Models;

public record AccountLoginViewModel(IEnumerable<ExternalProvider> ExternalProviders, string? ReturnUrl);

public record ExternalProvider(string DisplayName, string AuthenticationScheme);
