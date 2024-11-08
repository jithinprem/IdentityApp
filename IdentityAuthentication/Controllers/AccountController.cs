using System.Security.Claims;
using System.Text;
using IdentityAuthentication.DTOs;
using IdentityAuthentication.Models;
using IdentityAuthentication.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;

namespace IdentityAuthentication.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AccountController : Controller
{

    private readonly JWTService _jwtService;
    private readonly SignInManager<User> _signInManager;
    private readonly UserManager<User> _userManager;
    private readonly EmailService _emailService;
    private readonly IConfiguration _config;
    public AccountController(JWTService jwtService, SignInManager<User> signInManager, UserManager<User> userManager, EmailService emailService, IConfiguration config)
    {
        // signInManager is responsible for sign the user in
        // UserManager is responsible for creating the user
        _jwtService = jwtService;
        _userManager = userManager;
        _signInManager = signInManager;
        _emailService = emailService;
        _config = config;
    }

    [Authorize]
    [HttpGet("refresh-user-token")]
    public async Task<ActionResult<UserDto>> RefreshUserToken()
    {
        var user = await _userManager.FindByNameAsync(User.FindFirst(ClaimTypes.Email)?.Value);
        return CreateApplicationUserDto(user);
    }

    [HttpPost("login")]
    public async Task<ActionResult<UserDto>> Login(LoginDto model)
    {
        var user = await _userManager.FindByNameAsync(model.UserName); // findByNameAsync is coming form Microsoft Identity
        if (user == null) return Unauthorized("Invalid username or password");
        if (user.EmailConfirmed == false) return Unauthorized("please confirm your email.");

        var result = await _signInManager.CheckPasswordSignInAsync(user, model.Password, false);
        if (!result.Succeeded) return Unauthorized("Invalid username or password");
        return CreateApplicationUserDto(user);
    }
    
    [HttpPost("register")]
    public async Task<IActionResult> Register(RegisterDto model) {
        if (await CheckEmailExistAsync(model.Email))
        {
            return BadRequest($"An existing account is using {model.Email}, please try another email address");
        }

        var userToAdd = new User
        {
            FirstName = model.FirstName.ToLower(),
            LastName = model.LastName.ToLower(),
            UserName = model.Email.ToLower(),
            Email = model.Email.ToLower(),
            // EmailConfirmed = true  //removing hardcoding of letting the email confirmation as true
        };
        var result = await _userManager.CreateAsync(userToAdd, model.Password);
        if (!result.Succeeded) return BadRequest(result.Errors);

        try
        {
            if (await SendConfirmEmailAsync(userToAdd))
            {
                return Ok(new JsonResult(new {title ="Account Created",  message = "Your account has been created. Please confirm your email address" }));
            }
            return BadRequest("failed to send email, Please contact admin");
        }
        catch(Exception)
        {
            return BadRequest("failed to send email, Please contact admin");
        }

    }

    [HttpPut("confirm-email")]
    public async Task<IActionResult> ConfirmEmail(ConfirmEmailDto model)
    {
        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user == null) return Unauthorized("this email have not been registered yet");
        if (user.EmailConfirmed == true)
            return BadRequest("Your email was confirmed before. Please login to your account");
        try
        {
            var decodedTokenBytes = WebEncoders.Base64UrlDecode(model.Token);
            var decodedToken = Encoding.UTF8.GetString(decodedTokenBytes);

            var result = await _userManager.ConfirmEmailAsync(user, decodedToken);
            if (result.Succeeded)
            {
                return Ok(new JsonResult(new
                    { title = "Email Confirmed", message = "Your email address is confirmed. You can login now." }));
            }

            return BadRequest("Invalid Token. Please try again");
        }
        catch (Exception)
        {
            return BadRequest("Invalid token, please try again");
        }
    }

    [HttpPost("resend-email-confirmation-link/{email}")]
    public async Task<IActionResult> ResendEmailConfirmationLink(string email)
    {
        if (string.IsNullOrEmpty(email)) return BadRequest("invalid email");
        var user = await _userManager.FindByEmailAsync(email);
        if (user == null) return Unauthorized("this email address has not been registered yet");
        if (user.EmailConfirmed == true)
            return BadRequest("your email address was confirmed before. Please login to your account.");
        try
        {
            if (await SendConfirmEmailAsync(user))
            {
                return Ok(new JsonResult(new {title ="Confirmation link send",  message = "Please confirm your email address" }));
            }
            return BadRequest("failed to send email, Please contact admin");
        }
        catch (Exception)
        {
            return BadRequest("failed to send email, Please contact admin");
        }
    }
    
    [HttpPost("forgot-username-or-password/{email}")]
    public async Task<IActionResult> ForgotUserNameOrPassword(string email)
    {
        if (string.IsNullOrEmpty(email)) return BadRequest("Invalid email address");
        var user = await _userManager.FindByEmailAsync(email);

        if (user == null)
            return Unauthorized("This email address have not been registered yet");
        if (user.EmailConfirmed == false)
            return BadRequest("Your email address was not confirmed before. Please confirm your email account");
        try
        {
            if (await SendForgotUserNameOrPasswordEmail(user))
            {
                return Ok(new JsonResult(new { title = "Forgot username or password email sent", message = "Please check your email" }));
            }

            return BadRequest("Failed to send email. Please contact the admin");
        }
        catch (Exception)
        {
            return BadRequest("Failed to send email. Please contact the admin");
        }
    }

    [HttpPut("reset-password")]
    public async Task<IActionResult> ResetPassword(ResetPasswordDto resetPasswordDto)
    {
        var user = await _userManager.FindByEmailAsync(resetPasswordDto.Email);
        if (user == null) return Unauthorized("This email has not been registerd yet!");
        if (user.EmailConfirmed == false) return BadRequest("Please confirm your email");
        try
        {
            var decodedTokenBytes = WebEncoders.Base64UrlDecode(resetPasswordDto.Token);
            var decodedToken = Encoding.UTF8.GetString(decodedTokenBytes);

            var result = await _userManager.ResetPasswordAsync(user, decodedToken, resetPasswordDto.NewPassword);
            if (result.Succeeded)
            {
                return Ok(new JsonResult(new
                    { title = "Password Changed", message = "You can login now." }));
            }

            return BadRequest("Invalid Token, please try again.");
        }
        catch
        {
            return BadRequest("Invalid Token, please try again.");
        }
    }



    #region Private Helper Methods

    private async Task<bool> SendForgotUserNameOrPasswordEmail(User user)
    {
        var token = await _userManager.GeneratePasswordResetTokenAsync(user);
        token = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
        var url = $"{_config["JWT:ClientUrl"]}/{_config["Email:ResetPasswordPath"]}?token={token}&email={user.Email}";
        var body = $"<p>Hello: {user.FirstName} {user.LastName} </p>" +
                   $"<p>Username : {user.UserName}</p>" +
                   $"<p>Inorder to reset your password, please click on the following link</p>" +
                   $"<p><a href=\"{url}\">click here</a></p>" +
                   $"<p>Thank you,</p>" +
                   $"<br>{_config["Email:ApplicationName"]}";
        var emailSendModel = new EmailSendDto(user.Email, "Reset your password", body);
        return await _emailService.SendEmailAsync(emailSendModel);
    }

    private async Task<bool> SendConfirmEmailAsync(User user)
    {
        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        // encoding here and we decode it from confirm-email endpoint
        token = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
        var url = $"{_config["JWT:ClientUrl"]}/{_config["Email:ConfirmEmailPath"]}?token={token}&email={user.Email}";

        var body = $"<p>Hello: {user.FirstName} {user.LastName} </p>" +
                   $"<p>Please confirm your email address by clicking on the following link.</p>" +
                   $"<p><a href=\"{url}\">click here</a></p>" +
                   $"<p>Thank you,</p>" +
                   $"<br>{_config["Email:ApplicationName"]}";

        var emailSendModel = new EmailSendDto(user.Email, "Confirm your email", body);
        return await _emailService.SendEmailAsync(emailSendModel);
    }

    private async Task<bool> CheckEmailExistAsync(string email)
    {
        return await _userManager.Users.AnyAsync(x => x.Email == email.ToLower());
    }

    private UserDto CreateApplicationUserDto(User user)
    {
        return new UserDto
        {
            FirstName = user.FirstName,
            LastName = user.LastName,
            JWT = _jwtService.CreateJWT(user)
        };
    }
    #endregion
}