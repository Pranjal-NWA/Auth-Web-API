using WebAPI.Data;
using WebAPI.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

if (!builder.Environment.IsDevelopment())
{
    using var secretsClient = new Amazon.SecretsManager.AmazonSecretsManagerClient();
    var secretName = builder.Configuration["AWS:SecretName"] ?? "authservice/prod";
    var response = await secretsClient.GetSecretValueAsync(
        new Amazon.SecretsManager.Model.GetSecretValueRequest { SecretId = secretName });

    // Secret is stored in AWS as one JSON blob shaped like appsettings.json's
    // own nested structure, e.g. {"ConnectionStrings":{"DefaultConnection":"..."},"Jwt":{"SecretKey":"..."}}
    using var stream = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(response.SecretString));
    builder.Configuration.AddJsonStream(stream);
}

var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
if (string.IsNullOrWhiteSpace(connectionString))
    throw new InvalidOperationException("Database connection string is not configured.");

var jwtSecret = builder.Configuration["Jwt:SecretKey"];
if (string.IsNullOrWhiteSpace(jwtSecret))
    throw new InvalidOperationException("JWT secret key is not configured.");

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseNpgsql(connectionString));

builder.Services.AddDataProtection();

builder.Services
    .AddIdentityCore<ApplicationUser>(options =>
    {
        options.Password.RequiredLength = 8;
        options.Password.RequireDigit = true;
        options.Password.RequireUppercase = true;
        options.Password.RequireNonAlphanumeric = true;
        options.User.RequireUniqueEmail = true;


        options.Lockout.MaxFailedAccessAttempts = 5;
        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    })
    .AddRoles<IdentityRole<Guid>>()               
    .AddEntityFrameworkStores<AppDbContext>()
    .AddDefaultTokenProviders();      

    if (builder.Environment.IsDevelopment())
{
    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddSwaggerGen();
}            

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}


using (var scope = app.Services.CreateScope())
{
    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole<Guid>>>();
    foreach (var role in new[] { "Admin", "User" })
    {
        if (!await roleManager.RoleExistsAsync(role))
            await roleManager.CreateAsync(new IdentityRole<Guid>(role));
    }
}


app.MapGet("/healthz", async (AppDbContext db) =>
{
    try
    {
        await db.Database.CanConnectAsync();
        return Results.Ok(new { status = "ok", db = "ok" });
    }
    catch
    {
        return Results.Json(new { status = "error", db = "unreachable" }, statusCode: 503);
    }
});

app.Run();