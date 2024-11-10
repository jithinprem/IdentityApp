using System.ComponentModel.DataAnnotations;

namespace IdentityAuthentication.DTOs.Admin;

public class MemberAddEditDto
{
    public string Id { get; set; } // id cannot be required => when admin adding an user => id is not set
    [Required]
    public string UserName { get; set; }
    [Required]
    public string FirstName { get; set; }
    [Required]
    public string LastName { get; set; }
    public string Password { get; set; } // not attributed with required because admin might only want to change the first, last name
    [Required]
    public string Roles { get; set; } // this is string => eg "Admin,Player,Manager"
    
}