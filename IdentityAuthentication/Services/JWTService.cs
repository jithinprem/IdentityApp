﻿using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using IdentityAuthentication.Models;
using Microsoft.IdentityModel.Tokens;

namespace IdentityAuthentication.Services;

public class JWTService
{
    private readonly IConfiguration _configuration;
    private readonly SymmetricSecurityKey _jwtKey;
    
    public JWTService(IConfiguration configuration)
    {
        _configuration = configuration;
        // jwtKey is used for encrypting and decrypting tokens
        _jwtKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Key"]));
    }

    public string CreateJWT(User user)
    {
        var userClaims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id),
            new Claim(ClaimTypes.Email, user.UserName),
            new Claim(ClaimTypes.GivenName, user.FirstName),
            new Claim(ClaimTypes.Surname, user.LastName)
        };

        var credentials = new SigningCredentials(_jwtKey, SecurityAlgorithms.HmacSha256Signature);
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(userClaims),
            Expires = DateTime.UtcNow.AddDays(int.Parse(_configuration["JWT:ExpiresInDays"])),
            SigningCredentials = credentials,
            Issuer = _configuration["JWT:Issuer"]
        };
        var tokenHandler = new JwtSecurityTokenHandler();
        var jwt = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(jwt); 
    }
}