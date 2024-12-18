﻿using IdentityAuthentication.DTOs.Admin;
using IdentityAuthentication.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace IdentityAuthentication.Controllers;

[Authorize(Roles = "Admin")]
[Route("api/[controller]")]
[ApiController]
public class AdminController: Controller
{
    private readonly UserManager<User> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;

    public AdminController(
        UserManager<User> userManager,
        RoleManager<IdentityRole> roleManager)
    {
        _userManager = userManager;
        _roleManager = roleManager;
    }

    [HttpGet("get-members")]
    public async Task<ActionResult<IEnumerable<MemberViewDto>>> GetMembers()
    {
        var members = await _userManager.Users.Where(x => x.UserName != SD.AdminUserName)
            .Select(member => new MemberViewDto // projecting into MemberViewDto (member is of User type)
            {
                Id = member.Id,
                UserName = member.UserName,
                FirstName = member.FirstName,
                LastName = member.LastName,
                DateCreated = member.DateCreated,
                IsLocked = _userManager.IsLockedOutAsync(member).GetAwaiter()
                    .GetResult(), // used for places where you need to use await
                Roles = _userManager.GetRolesAsync(member).GetAwaiter().GetResult()

            }).ToListAsync();
        
        return Ok(members);
    }

    [HttpPut("lock-member/{id}")]
    public async Task<IActionResult> LockMember(string id)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null) return NotFound();

        if (IsAdminUserId(id))
        {
            return BadRequest(SD.SuperAdminChangeNotAllowed);
        }

        await _userManager.SetLockoutEndDateAsync(user, DateTime.UtcNow.AddDays(5));
        return NoContent();
    }

    [HttpPut("unlock-member/{id}")]
    public async Task<IActionResult> UnlockMember(string id)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null) return NotFound();

        if (IsAdminUserId(id))
        {
            return BadRequest(SD.SuperAdminChangeNotAllowed);
        }

        await _userManager.SetLockoutEndDateAsync(user, null);
        return NoContent();
    }

    [HttpDelete("delete-member/{id}")]
    public async Task<IActionResult> DeleteMember(string id)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null) return NotFound();

        if (IsAdminUserId(id))
        {
            return BadRequest(SD.SuperAdminChangeNotAllowed);
        }

        await _userManager.DeleteAsync(user);
        return NoContent();
    }


    [HttpGet("get-application-roles")]
    public async Task<ActionResult> GetApplicationRoles()
    {
        return Ok(await _roleManager.Roles.Select(x => x.Name).ToListAsync());
    }
    
    [HttpGet("get-member/{id}")]
    public async Task<ActionResult<MemberAddEditDto>> GetMember(string id)
    {
        var mem = await _userManager.Users
            .Where(x => x.UserName != SD.AdminUserName && x.Id == id)
            .Select(member => new MemberAddEditDto
            {
                Id = member.Id,
                FirstName = member.FirstName,
                LastName = member.LastName,
                UserName = member.UserName,
                Roles = string.Join(",", _userManager.GetRolesAsync(member).GetAwaiter().GetResult())
                
            }).FirstOrDefaultAsync();
        return Ok(mem);
    }

    [HttpPost("add-edit-member")]
    public async Task<IActionResult> AddEditMember(MemberAddEditDto model)
    {
        User user;
        if (string.IsNullOrEmpty(model.Id))
        {
            // adding a user
            if (string.IsNullOrEmpty(model.Password) || model.Password.Length < 6)
            {
                ModelState.AddModelError("errors", "Password must be atleast 6 characters");
                return BadRequest(ModelState);
            }

            user = new User
            {
                FirstName = model.FirstName.ToLower(),
                LastName = model.LastName.ToLower(),
                UserName = model.UserName.ToLower(),
                EmailConfirmed = true
            };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
            {
                return BadRequest(result.Errors);
            }
        }
        else
        {
            // editing an existing user
            user = await _userManager.FindByIdAsync(model.Id);
            if(!string.IsNullOrEmpty(model.Password))
            {
                if (model.Password.Length < 6)
                {
                    ModelState.AddModelError("errors", "Password must be atleast 6 characters");
                    return BadRequest(ModelState);
                }
            }
            if (IsAdminUserId(model.Id))
            {
                return BadRequest(SD.SuperAdminChangeNotAllowed);
            }

            if (user == null) return NotFound();

            user.FirstName = model.FirstName.ToLower();
            user.LastName = model.LastName.ToLower();
            user.UserName = model.UserName.ToLower();

            if (!string.IsNullOrEmpty(model.Password))
            {
                await _userManager.RemovePasswordAsync(user);
                await _userManager.AddPasswordAsync(user, model.Password);
            }
        }

        var userRoles = await _userManager.GetRolesAsync(user);
        //remove users existing roles
        await _userManager.RemoveFromRolesAsync(user, userRoles);
        //adding the new roles provided
        foreach (var role in model.Roles.Split(",").ToArray())
        {
            var roleToAdd = await _roleManager.Roles.FirstOrDefaultAsync(r => r.Name == role);
            if (roleToAdd != null)
            {
                await _userManager.AddToRoleAsync(user, role);
            }
        }

        if (string.IsNullOrEmpty(model.Id))
        {
            return Ok(new JsonResult(new {title ="Account Created",  message = $"{model.UserName} has been created" }));
        }
        else
        {
            return Ok(new JsonResult(new {title ="Member Edited",  message = $"{model.UserName} has been updated" }));
        }
           
        
    }



    #region Helper methods

    private bool IsAdminUserId(string userId)
    {
        return _userManager.FindByIdAsync(userId).GetAwaiter().GetResult().UserName.Equals(SD.AdminUserName);
    }

    #endregion
    

}