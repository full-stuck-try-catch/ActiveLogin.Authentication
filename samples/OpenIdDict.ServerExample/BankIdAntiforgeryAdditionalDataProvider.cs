using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Http;

namespace OpenIdDict.ServerExample;

/// <summary>
/// Custom antiforgery data provider that allows authentication state to change during BankID authentication
/// </summary>
public class BankIdAntiforgeryAdditionalDataProvider : IAntiforgeryAdditionalDataProvider
{
    public string GetAdditionalData(HttpContext context)
    {
        // Return empty string to not tie the token to any specific user
        return string.Empty;
    }

    public bool ValidateAdditionalData(HttpContext context, string additionalData)
    {
        // Always return true to allow user identity to change during authentication flow
        return true;
    }
}
