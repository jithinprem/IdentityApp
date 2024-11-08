using System.ComponentModel.DataAnnotations;

namespace IdentityAuthentication.DTOs;

public class ResetPasswordDto
{
    [Required]
    public string Token { get; set; }
    [Required]
    [EmailAddress]
    public string Email { get; set; }
    [Required]
    [StringLength(15, MinimumLength = 6, ErrorMessage = "New password must be of minimum {2} and maximum {1} long.")]
    public string NewPassword { get; set; }
    
}