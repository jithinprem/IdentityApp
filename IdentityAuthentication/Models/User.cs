using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;

namespace IdentityAuthentication.Models;

public class User: IdentityUser
{
    // our user is deriving from IdentityUser
    [Required]
    public string FirstName { get; set; }
    [Required]
    public string LastName { get; set; }
    public DateTime DateCreated { get; set; } = DateTime.UtcNow;
    public string? Provider { get; set; }
}