using Microsoft.EntityFrameworkCore;

namespace OpenIdDict.ServerExample;

public class ApplicationDbContext : DbContext
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }
}
