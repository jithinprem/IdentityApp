using Microsoft.AspNetCore.Mvc;

namespace IdentityAuthentication.Controllers;

public class HomeController : Controller
{
    // GET
    [HttpGet("/")]
    public string Index()
    {
        return "welcome to application";
    }
}