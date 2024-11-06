using System.Security.Claims;
using IdentityAuthentication.DTOs;
using IdentityAuthentication.Models;
using IdentityAuthentication.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace IdentityAuthentication.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AccountController : Controller
{

    private readonly JWTService _jwtService;
    private readonly SignInManager<User> _signInManager;
    private readonly UserManager<User> _userManager;

    public AccountController(JWTService jwtService, SignInManager<User> signInManager, UserManager<User> userManager)
    {
        // signInManager is responsible for sign the user in
        // UserManager is responsible for creating the user
        _jwtService = jwtService;
        _userManager = userManager;
        _signInManager = signInManager;
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
            EmailConfirmed = true
        };
        var result = await _userManager.CreateAsync(userToAdd, model.Password);
        if (!result.Succeeded) return BadRequest(result.Errors);

        return Ok("Your account has been created successfully");
    }


    #region Private Helper Methods

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