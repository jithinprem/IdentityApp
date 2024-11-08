using System.Text;
using IdentityAuthentication.Data;
using IdentityAuthentication.Models;
using IdentityAuthentication.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddControllers();
builder.Services.AddDbContext<Context>(options =>
{
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));
});

builder.Services.AddScoped<JWTService>();
builder.Services.AddScoped<EmailService>();

builder.Services.AddIdentityCore<User>(options =>
    {
        // password configuration
        options.Password.RequiredLength = 6;
        options.Password.RequireDigit = false;
        options.Password.RequireLowercase = false;
        options.Password.RequireUppercase = false;
        options.Password.RequireNonAlphanumeric = false;

        // for email confirmation
        options.SignIn.RequireConfirmedEmail = true;
    })
    .AddRoles<IdentityRole>() // be able to add roles
    .AddRoleManager<RoleManager<IdentityRole>>() // be able to make use of RoleManager
    .AddEntityFrameworkStores<Context>() // providing our context
    .AddSignInManager<SignInManager<User>>() // make use of UserManger to create users
    .AddUserManager<UserManager<User>>() // be able to create tokens for email confirmation
    .AddDefaultTokenProviders(); // be able to create tokens for email confirmation

// to be able to authenticate our user using JWT
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true, // we are going to validate token based on the key
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JWT:key"])), // same key we used to encrypt for JWTService createJWT
            ValidateIssuer = true, 
            ValidateAudience = false, // do not validate the audience (angular side)
            ValidIssuer = builder.Configuration["JWT:Issuer"]
        };
    });
builder.Services.AddAuthorization();
builder.Services.AddCors();

builder.Services.Configure<ApiBehaviorOptions>(options =>
{
    options.InvalidModelStateResponseFactory = actionContext =>
    {
        var errors = actionContext.ModelState
            .Where(x => x.Value.Errors.Count > 0)
            .SelectMany(x => x.Value.Errors)
            .Select(x => x.ErrorMessage).ToArray();

        var toReturn = new
        {
            Errors = errors
        };
        return new BadRequestObjectResult(toReturn);
    };
});

var app = builder.Build();
app.Use(async (HttpContext context, Func<Task> next) =>
{   // dummy middleware to check TODO: delete
    var cont = context;
    await next();
});

app.UseRouting();
app.UseCors(opt =>
{
    opt.AllowAnyHeader().AllowAnyMethod().AllowCredentials().WithOrigins(builder.Configuration["JWT:ClientUrl"]);
});

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}
app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.Run();
