using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Moq;
using WebAPI.Controllers;
using WebAPI.DTOs;
using WebAPI.Services;
using Xunit;

namespace WebAPI.Tests;

public class UsersControllerTests
{
    private readonly Mock<IUserService> _userServiceMock;
    private readonly UsersController _controller;

    public UsersControllerTests()
    {
        _userServiceMock = new Mock<IUserService>();
        _controller = new UsersController(_userServiceMock.Object);
    }

    private void SetUser(ClaimsPrincipal user)
    {
        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext
            {
                User = user
            }
        };
    }

    [Fact]
    public async Task GetMe_ValidUser_ReturnsOkWithProfile()
    {
        // Arrange
        var userId = Guid.NewGuid();

        var profile = new UserResponse
        {
            Id = userId,
            Email = "test@example.com"
        };

        _userServiceMock
            .Setup(x => x.GetProfileAsync(userId))
            .ReturnsAsync(profile);

        SetUser(
            new ClaimsPrincipal(
                new ClaimsIdentity(
                    new[]
                    {
                        new Claim(
                            JwtRegisteredClaimNames.Sub,
                            userId.ToString())
                    },
                    "TestAuth")));

        // Act
        var result = await _controller.GetMe();

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        var returnedProfile = Assert.IsType<UserResponse>(okResult.Value);

        Assert.Equal(userId, returnedProfile.Id);
        Assert.Equal("test@example.com", returnedProfile.Email);

        _userServiceMock.Verify(
            x => x.GetProfileAsync(userId),
            Times.Once);
    }

    [Fact]
    public async Task GetMe_NoSubClaim_ReturnsUnauthorized()
    {
        // Arrange
        SetUser(
            new ClaimsPrincipal(
                new ClaimsIdentity(
                    Array.Empty<Claim>(),
                    "TestAuth")));

        // Act
        var result = await _controller.GetMe();

        // Assert
        Assert.IsType<UnauthorizedResult>(result);

        _userServiceMock.Verify(
            x => x.GetProfileAsync(It.IsAny<Guid>()),
            Times.Never);
    }

    [Fact]
    public async Task GetMe_InvalidSubClaim_ReturnsUnauthorized()
    {
        // Arrange
        SetUser(
            new ClaimsPrincipal(
                new ClaimsIdentity(
                    new[]
                    {
                        new Claim(
                            JwtRegisteredClaimNames.Sub,
                            "not-a-guid")
                    },
                    "TestAuth")));

        // Act
        var result = await _controller.GetMe();

        // Assert
        Assert.IsType<UnauthorizedResult>(result);

        _userServiceMock.Verify(
            x => x.GetProfileAsync(It.IsAny<Guid>()),
            Times.Never);
    }

    [Fact]
    public async Task GetMe_ProfileNotFound_ReturnsUnauthorized()
    {
        // Arrange
        var userId = Guid.NewGuid();

        _userServiceMock
            .Setup(x => x.GetProfileAsync(userId))
            .ReturnsAsync((UserResponse?)null);

        SetUser(
            new ClaimsPrincipal(
                new ClaimsIdentity(
                    new[]
                    {
                        new Claim(
                            JwtRegisteredClaimNames.Sub,
                            userId.ToString())
                    },
                    "TestAuth")));

        // Act
        var result = await _controller.GetMe();

        // Assert
        Assert.IsType<UnauthorizedResult>(result);

        _userServiceMock.Verify(
            x => x.GetProfileAsync(userId),
            Times.Once);
    }
}