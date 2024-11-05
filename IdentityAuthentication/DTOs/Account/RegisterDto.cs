using System.ComponentModel.DataAnnotations;
using System.Runtime.InteropServices.JavaScript;

namespace IdentityAuthentication.DTOs;

public class RegisterDto
{
    [Required]
    [StringLength(15, MinimumLength = 3, ErrorMessage = "First name must be atleast {2} and maximum {1} characters")]
    public string FirstName { get; set; }
    [Required]
    public string LastName { get; set; }
    [Required]
    [RegularExpression("^\\w+@[a-zA-Z_]+?\\.[a-zA-Z]{2,3}$", ErrorMessage = "invalid email address")]
    public string Email { get; set; }
    [Required]
    public string Password { get; set; }
}