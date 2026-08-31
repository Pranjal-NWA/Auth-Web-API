using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using WebAPI.Data;
using WebAPI.Models;
using WebAPI.Services;
using Xunit;

namespace WebAPI.Tests;

public class UserServiceTests
{
    private static (
        AppDbContext db,
        UserManager<ApplicationUser> userManager,
        ServiceProvider provider)
        NewIdentityStack()
    {
        var services = new ServiceCollection();

        var dbName = Guid.NewGuid().ToString();

        services.AddDbContext<AppDbContext>(
            options => options.UseInMemoryDatabase(dbName));

        services
            .AddIdentityCore<ApplicationUser>()
            .AddRoles<IdentityRole<Guid>>()
            .AddEntityFrameworkStores<AppDbContext>()
            .AddDefaultTokenProviders();

        services.AddLogging();
        services.AddDataProtection();
        services.AddAuthentication();

        var provider = services.BuildServiceProvider();

        var db = provider.GetRequiredService<AppDbContext>();

        var userManager =
            provider.GetRequiredService<UserManager<ApplicationUser>>();

        var roleManager =
            provider.GetRequiredService<RoleManager<IdentityRole<Guid>>>();

        roleManager
            .CreateAsync(new IdentityRole<Guid>("User"))
            .GetAwaiter()
            .GetResult();

        return (db, userManager, provider);
    }

    [Fact]
    public async Task GetProfileAsync_UserNotFound_ReturnsNull()
    {
        // Arrange
        var (_, userManager, _) = NewIdentityStack();
        var sut = new UserService(userManager);

        // Act
        var result = await sut.GetProfileAsync(Guid.NewGuid());

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task GetProfileAsync_InactiveUser_ReturnsNull()
    {
        // Arrange
        var (_, userManager, _) = NewIdentityStack();

        var user = new ApplicationUser
        {
            Id = Guid.NewGuid(),
            UserName = "inactive@example.com",
            Email = "inactive@example.com",
            IsActive = false
        };

        var createResult =
            await userManager.CreateAsync(user, "Testpass1!");

        Assert.True(createResult.Succeeded);

        var sut = new UserService(userManager);

        // Act
        var result = await sut.GetProfileAsync(user.Id);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task GetProfileAsync_LockedOutUser_ReturnsNull()
    {
        // Arrange
        var (_, userManager, _) = NewIdentityStack();

        var user = new ApplicationUser
        {
            Id = Guid.NewGuid(),
            UserName = "locked@example.com",
            Email = "locked@example.com",
            IsActive = true
        };

        var createResult =
            await userManager.CreateAsync(user, "Testpass1!");

        Assert.True(createResult.Succeeded);

        await userManager.SetLockoutEndDateAsync(
            user,
            DateTimeOffset.UtcNow.AddMinutes(10));

        var sut = new UserService(userManager);

        // Act
        var result = await sut.GetProfileAsync(user.Id);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task GetProfileAsync_ActiveUnlockedUser_ReturnsProfile()
    {
        // Arrange
        var (_, userManager, _) = NewIdentityStack();

        var user = new ApplicationUser
        {
            Id = Guid.NewGuid(),
            UserName = "user@example.com",
            Email = "user@example.com",
            FullName = "Test User",
            EmailConfirmed = true,
            IsActive = true,
            CreatedAt = DateTime.UtcNow
        };

        var createResult =
            await userManager.CreateAsync(user, "Testpass1!");

        Assert.True(createResult.Succeeded);

        await userManager.AddToRoleAsync(user, "User");

        var sut = new UserService(userManager);

        // Act
        var result = await sut.GetProfileAsync(user.Id);

        // Assert
        Assert.NotNull(result);

        Assert.Equal(user.Id, result.Id);
        Assert.Equal(user.Email, result.Email);
        Assert.Equal(user.FullName, result.FullName);
        Assert.True(result.IsVerified);
        Assert.Equal("User", result.Role);
        Assert.Equal(user.CreatedAt, result.CreatedAt);
    }
    [Fact]
    public async Task GetProfileAsync_UserWithoutRole_ReturnsDefaultUserRole()
    {
        // Arrange
        var (_, userManager, _) = NewIdentityStack();

        var user = new ApplicationUser
        {
            Id = Guid.NewGuid(),
            UserName = "norole@example.com",
            Email = "norole@example.com",
            FullName = "No Role User",
            EmailConfirmed = true,
            IsActive = true,
            CreatedAt = DateTime.UtcNow
        };

        var createResult =
            await userManager.CreateAsync(user, "Testpass1!");

        Assert.True(createResult.Succeeded);

        var sut = new UserService(userManager);

        // Act
        var result = await sut.GetProfileAsync(user.Id);

        // Assert
        Assert.NotNull(result);
        Assert.Equal("User", result.Role);
    }
}