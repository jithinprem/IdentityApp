using System.Security.Claims;
using IdentityAuthentication.Data;
using IdentityAuthentication.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace IdentityAuthentication.Services;

// class responsible for seeding applying pending migration and seeding into our database 
public class ContextSeedService
{
    private readonly Context _context;
    private readonly UserManager<User> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;

    public ContextSeedService(Context context, UserManager<User> userManager, RoleManager<IdentityRole> roleManager)
    {
        _context = context;
        _userManager = userManager;
        _roleManager = roleManager;
    }

    public async Task InitializeContextAsync()
    {
        if (_context.Database.GetPendingMigrationsAsync().GetAwaiter().GetResult().Count() > 0)
        {
            // applies any pending migration into our database
            await _context.Database.MigrateAsync();
        }

        if (!_roleManager.Roles.Any())
        {
            await _roleManager.CreateAsync(new IdentityRole { Name = SD.AdminRole });
            await _roleManager.CreateAsync(new IdentityRole { Name = SD.ManagerRole });
            await _roleManager.CreateAsync(new IdentityRole { Name = SD.PlayerRole });
        }

        if (!_userManager.Users.AnyAsync().GetAwaiter().GetResult())
        {
            var admin = new User
            {
                FirstName = "admin",
                LastName = "jackson",
                UserName = SD.AdminUserName,
                Email = SD.AdminUserName,
                EmailConfirmed = true
            };
            await _userManager.CreateAsync(admin, "Abc@123");
            await _userManager.AddToRolesAsync(admin, new[] { SD.AdminRole, SD.ManagerRole, SD.PlayerRole });
            await _userManager.AddClaimsAsync(admin, new Claim[]
            {
                new Claim(ClaimTypes.Email, admin.Email),
                new Claim(ClaimTypes.GivenName, admin.FirstName),
                new Claim(ClaimTypes.Surname, admin.LastName)
            });
            
            var manager = new User
            {
                FirstName = "manager",
                LastName = "jackson",
                UserName = "manager@example.com",
                Email = "manager@example.com",
                EmailConfirmed = true
            };
            await _userManager.CreateAsync(manager, "Abc@123");
            await _userManager.AddToRoleAsync(manager, SD.ManagerRole);
            await _userManager.AddClaimsAsync(manager, new Claim[]
            {
                new Claim(ClaimTypes.Email, manager.Email),
                new Claim(ClaimTypes.GivenName, manager.FirstName),
                new Claim(ClaimTypes.Surname, manager.LastName)
            });
            
            var player = new User
            {
                FirstName = "player",
                LastName = "jackson",
                UserName = "player@example.com",
                Email = "player@example.com",
                EmailConfirmed = true
            };
            await _userManager.CreateAsync(player, "Abc@123");
            await _userManager.AddToRoleAsync(player, SD.PlayerRole);
            await _userManager.AddClaimsAsync(player, new Claim[]
            {
                new Claim(ClaimTypes.Email, player.Email),
                new Claim(ClaimTypes.GivenName, player.FirstName),
                new Claim(ClaimTypes.Surname, player.LastName)
            });
            
            var vipPlayer = new User
            {
                FirstName = "vipPlayer",
                LastName = "jackson",
                UserName = "vipPlayer@example.com",
                Email = "vipPlayer@example.com",
                EmailConfirmed = true
            };
            await _userManager.CreateAsync(vipPlayer, "Abc@123");
            await _userManager.AddToRoleAsync(vipPlayer, SD.PlayerRole);
            await _userManager.AddClaimsAsync(vipPlayer, new Claim[]
            {
                new Claim(ClaimTypes.Email, vipPlayer.Email),
                new Claim(ClaimTypes.GivenName, vipPlayer.FirstName),
                new Claim(ClaimTypes.Surname, vipPlayer.LastName)
            });


        }
    }
}