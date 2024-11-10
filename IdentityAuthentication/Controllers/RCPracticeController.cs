using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityAuthentication.Controllers;

[Route("api/[controller]")]
[ApiController]
public class RCPracticeController : Controller
{
    // GET
    [HttpGet("public")]
    public IActionResult Index()
    {
        return Ok("public");
    }

    #region Roles

    [HttpGet("admin-role")]
    [Authorize(Roles = "Admin")]
    public IActionResult AdminRole()
    {
        return Ok("admin role");
    }
    
    [HttpGet("manager-role")]
    [Authorize(Roles = "Manager")]
    public IActionResult ManagerRole()
    {
        return Ok("manager role");
    }

    
    [HttpGet("player-role")]
    [Authorize(Roles = "Player")]
    public IActionResult PlayerRole()
    {
        return Ok("player role");
    }

    
    [HttpGet("vip-player-role")]
    [Authorize(Roles = "Player")]
    public IActionResult VipPlayerRole()
    {
        return Ok("vip player (player) role");
    }
    
    [HttpGet("admin-or-manager-role")]
    [Authorize(Roles = "Manager,Admin")]
    public IActionResult AdminOrManagerRole()
    {
        return Ok("admin and manager role");
    }
    #endregion

    #region Role Policy

    [HttpGet("admin-policy")]
    [Authorize(Policy = "AdminPolicy")]
    public IActionResult AdminPolicy()
    {
        return Ok("admin policy");
    }
    [HttpGet("manager-policy")]
    [Authorize(Policy = "ManagerPolicy")]
    public IActionResult ManagerPolicy()
    {
        return Ok("manager policy");
    }

    [HttpGet("admin-or-manager-policy")]
    [Authorize(Policy = "AdminOrManagerPolicy")]
    public IActionResult AdminOrManagerPolicy()
    {
        return Ok("Admin Or manager Policy");
    }
    
    [HttpGet("admin-and-manager-policy")]
    [Authorize(Policy = "AdminAndManagerPolicy")]
    public IActionResult AdminAndManagerPolicy()
    {
        return Ok("admin and manager policy");
    }
    
    [HttpGet("any-role-policy")]
    [Authorize(Policy = "AnyRolePolicy")]
    public IActionResult AnyRolePolicy()
    {
        return Ok("Any Role Policy");
    }
    #endregion

    #region Claim Policy
    
    [HttpGet("admin-email-claim-policy")]
    [Authorize(Policy = "AdminEmailPolicy")]
    public IActionResult SpecificAdminEmailClaimPolicy()
    {
        return Ok("admin email policy");
    }
    
    [HttpGet("jackson-surname-claim-policy")]
    [Authorize(Policy = "JacksonSurNamePolicy")]
    public IActionResult JackSonSurnamePolicy()
    {
        return Ok("jackson surname email policy");
    }
    
    [HttpGet("manager-email-and-jackson-surname-claim-policy")]
    [Authorize(Policy = "ManagerEmailAndJacksonSurnamePolicy")]
    public IActionResult ManagerEmailAndJacksonSurnamePolicy()
    {
        return Ok("Manager email and Jackson Surname");
    }

    [HttpGet("vip-policy")]
    [Authorize(Policy = "VIPPolicy")]
    public IActionResult VipPolicy()
    {
        return Ok("vip policy");
    }


    #endregion
}