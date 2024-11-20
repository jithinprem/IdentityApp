using Microsoft.AspNetCore.Mvc;

namespace IdentityAuthentication.Controllers;

public class FallbackController : Controller
{
    // GET
    public IActionResult Index()
    {
        return PhysicalFile(Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "index.html"), "text/HTML");
    }
}