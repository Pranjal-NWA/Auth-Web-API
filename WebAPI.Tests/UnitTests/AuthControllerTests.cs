using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Moq;
using WebAPI.Controllers;
using WebAPI.DTOs;
using WebAPI.Models;
using WebAPI.Services;
using Xunit;

namespace WebAPI.Tests.UnitTests;

public class AuthControllerTests
{
    private static ApplicationUser CreateUser()
    {
        return new ApplicationUser
        {
            Id = Guid.NewGuid(),
            Email = "controller@example.com",
            UserName = "controller@example.com",
            FullName = "Controller Test",
            EmailConfirmed = true,
            CreatedAt = DateTime.UtcNow
        };
    }

    private static (AuthController controller, Mock<IAuthService> authServiceMock)
        CreateController(IConfiguration configuration)
    {
        var authServiceMock = new Mock<IAuthService>();
        var controller = new AuthController(authServiceMock.Object, configuration)
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext()
            }
        };

        return (controller, authServiceMock);
    }

    [Fact]
    public async Task Login_MissingExpiryConfiguration_UsesDefaultsAndSetsCookies()
    {
        // Arrange
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["CookieSecure"] = "false"
                // Jwt expiry values intentionally omitted.
            })
            .Build();

        var (controller, authServiceMock) = CreateController(config);
        var user = CreateUser();

        authServiceMock
            .Setup(x => x.LoginAsync(It.IsAny<LoginRequest>()))
            .ReturnsAsync((user, "access-token", "refresh-token"));

        authServiceMock
            .Setup(x => x.GetUserRoleAsync(user))
            .ReturnsAsync("User");

        // Act
        var result = await controller.Login(
            new LoginRequest
            {
                Email = user.Email!,
                Password = "Testpass1!"
            });

        // Assert
        var ok = Assert.IsType<OkObjectResult>(result.Result);
        var body = Assert.IsType<UserResponse>(ok.Value);

        Assert.Equal(user.Id, body.Id);
        Assert.Equal(user.Email, body.Email);
        Assert.Equal("User", body.Role);

        var setCookieHeaders =
            controller.HttpContext.Response.Headers["Set-Cookie"];

        Assert.Equal(2, setCookieHeaders.Count);
        Assert.Contains(
            setCookieHeaders,
            cookie => cookie.StartsWith("access_token=access-token"));
        Assert.Contains(
            setCookieHeaders,
            cookie => cookie.StartsWith("refresh_token=refresh-token"));
        Assert.Contains(
            setCookieHeaders,
            cookie => cookie.Contains("HttpOnly", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(
            setCookieHeaders,
            cookie => cookie.Contains("Max-Age=900", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(
            setCookieHeaders,
            cookie => cookie.Contains("Max-Age=2592000", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task ForgotPassword_CallsServiceAndReturnsNoContent()
    {
        // Arrange
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Frontend:BaseUrl"] = "https://frontend.example.com"
            })
            .Build();

        var (controller, authServiceMock) = CreateController(config);

        authServiceMock
            .Setup(x => x.ForgotPasswordAsync(
                "user@example.com",
                "https://frontend.example.com/reset-password?email={email}&token={token}"))
            .Returns(Task.CompletedTask);

        // Act
        var result = await controller.ForgotPassword(
            new ForgotPasswordRequest
            {
                Email = "user@example.com"
            });

        // Assert
        Assert.IsType<NoContentResult>(result);

        authServiceMock.Verify(
            x => x.ForgotPasswordAsync(
                "user@example.com",
                "https://frontend.example.com/reset-password?email={email}&token={token}"),
            Times.Once);
    }

    [Fact]
    public async Task ResetPassword_CallsServiceAndReturnsNoContent()
    {
        // Arrange
        var config = new ConfigurationBuilder().Build();

        var (controller, authServiceMock) = CreateController(config);

        var request = new ResetPasswordRequest
        {
            Email = "user@example.com",
            Token = "reset-token",
            NewPassword = "NewPass1!"
        };

        authServiceMock
            .Setup(x => x.ResetPasswordAsync(request))
            .Returns(Task.CompletedTask);

        // Act
        var result = await controller.ResetPassword(request);

        // Assert
        Assert.IsType<NoContentResult>(result);

        authServiceMock.Verify(
            x => x.ResetPasswordAsync(request),
            Times.Once);
    }

    [Fact]
    public async Task Refresh_WithoutCookie_ReturnsUnauthorized()
    {
        // Arrange
        var config = new ConfigurationBuilder().Build();
        var (controller, authServiceMock) = CreateController(config);

        // Act
        var result = await controller.Refresh();

        // Assert
        Assert.IsType<UnauthorizedObjectResult>(result.Result);

        authServiceMock.Verify(
            x => x.RefreshAsync(It.IsAny<string>()),
            Times.Never);
    }
}
