using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityAuthentication.Controllers;

[Authorize]
[Route("api/[controller]")]
[ApiController]
public class PlayController : Controller
{
    // GET
    [HttpGet("get-players")]
    public IActionResult Index()
    {
        return Ok(new JsonResult(new { message = "Only authorized users can view players" }));
    }
}