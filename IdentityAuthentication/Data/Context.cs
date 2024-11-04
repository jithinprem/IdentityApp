using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace IdentityAuthentication.Data;

/*
 * why derived from IdentityDbContext ? => its a base class for EntityFramework Database context used for Identity
 * and since we are using MicrosoftDbContext we go ahead with it
 */
public class Context: IdentityDbContext 
{
    public Context(DbContextOptions<Context> options) : base(options)
    {
        
    }
}